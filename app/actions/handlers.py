import asyncio
import logging
import httpx

import app.datasource.ctrack as client

from datetime import date, datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from gundi_core.schemas.v2 import LogLevel, Integration
from app.actions.configurations import (
    AuthenticateConfig,
    PullObservationsConfig,
    PullVehicleTripsConfig,
    TriggerFetchVehicleObservationsConfig,
    get_auth_config
)
from app.services.activity_logger import activity_logger, log_action_activity
from app.services.gundi import send_observations_to_gundi
from app.services.state import IntegrationStateManager
from app.services.utils import generate_batches
from app.services.action_scheduler import crontab_schedule

logger = logging.getLogger(__name__)
state_manager = IntegrationStateManager()

# Per-integration semaphore to serialize Ctrack API calls and avoid 429 thrashing
_ctrack_semaphores: Dict[str, asyncio.Semaphore] = {}
_semaphore_lock = asyncio.Lock()

# Max concurrent Ctrack API requests per integration (1 = fully serialized)
CTRACK_SEMAPHORE_LIMIT = 3


async def get_ctrack_semaphore(integration_id: str) -> asyncio.Semaphore:
    key = str(integration_id)
    async with _semaphore_lock:
        if key not in _ctrack_semaphores:
            _ctrack_semaphores[key] = asyncio.Semaphore(CTRACK_SEMAPHORE_LIMIT)
    return _ctrack_semaphores[key]


async def with_ctrack_semaphore(integration_id: str, coro):
    """Run a coroutine while holding the integration's Ctrack API semaphore."""
    sem = await get_ctrack_semaphore(integration_id)
    async with sem:
        return await coro


CTC_BASE_URL = "https://apim.ctrackcrystal.com/api"
INVALID_TRIP_ID = "0"
MAX_TOKEN_DISPLAY_LENGTH = 100
MAX_PULL_LOOKBACK_DAYS = 3


def date_range(start_date: date, end_date: date):
    """
        Yields a datetime at midnight for each day in the inclusive range from start_date to end_date.

        Args:
            start_date (date): The first date in the range.
            end_date (date): The last date in the range.

        Yields:
            datetime: A datetime object at midnight for each day in the range.
    """
    current = start_date
    while current <= end_date:
        yield datetime.combine(current, datetime.min.time()).replace(tzinfo=timezone.utc)
        current += timedelta(days=1)


def transform(observation: client.LocationSummary, vehicle: PullVehicleTripsConfig) -> dict:
    additional_info = {
        key: value for key, value in observation.dict().items() if value and key not in ["eventTime", "latitude", "longitude"]
    }

    return {
        "source_name": vehicle.vehicle_display_name,
        "source": vehicle.vehicle_id,
        "type": "tracking-device",
        "subject_type": "vehicle",
        "recorded_at": observation.event_time,
        "location": {
            "lat": observation.latitude,
            "lon": observation.longitude
        },
        "additional": {
            **additional_info
        }
    }


async def _fetch_one_vehicle_trips_observations(
    token: client.LoginResponse,
    auth_config: AuthenticateConfig,
    base_url: str,
    action_config: PullVehicleTripsConfig,
) -> Tuple[List[dict], int]:
    """
    Fetch trips and trip summaries for one vehicle/filter_day and return transformed observations.
    Does not send to Gundi or save state. Caller must hold Ctrack semaphore if limiting concurrency.
    Returns (transformed_data, observations_count). Raises client.TooManyRequestsException on 429.
    """
    transformed_data: List[dict] = []
    trips_response = await client.get_vehicle_trips(
        token.jwt,
        auth_config.subscription_key.get_secret_value(),
        base_url,
        action_config.vehicle_id,
        action_config.filter_day,
    )
    if not trips_response:
        return [], 0

    for trip in trips_response.payload:
        for trip_detail in trip.details:
            if trip_detail.trip_id == INVALID_TRIP_ID:
                logger.info(
                    f"Skipping trip detail date {trip_detail.date} for vehicle {action_config.vehicle_id} (tripId is 0)"
                )
                continue
            if action_config.vehicle_last_updated and trip_detail.trip_end_time <= action_config.vehicle_last_updated:
                logger.info(
                    f"Trip {trip_detail.trip_id} for vehicle {action_config.vehicle_id} is already processed. Skipping..."
                )
                continue
            logger.info(
                f"Getting trip summary for trip {trip_detail.trip_id} vehicle {action_config.vehicle_id} to extract observations..."
            )
            trip_summary = await client.get_trip_summary(
                token.jwt,
                auth_config.subscription_key.get_secret_value(),
                base_url,
                trip_detail.trip_id,
            )
            if trip_summary:
                transformed_data.extend([
                    transform(observation, action_config)
                    for observation in trip_summary.locationSummary
                ])
            else:
                logger.warning(
                    f"-- No trip summary returned for trip {trip_detail.trip_id} Vehicle ID {action_config.vehicle_id} --"
                )

    return transformed_data, len(transformed_data)


async def retrieve_token(integration: Integration, base_url: str) -> client.LoginResponse:
    """
    Helper function to retrieve token from state or CTC API.
    May raise client.TooManyRequestsException after retries if the API returns 429.
    """
    saved_token = await state_manager.get_state(
        str(integration.id),
        "auth",
        "token"
    )

    auth_config = None
    if not saved_token:
        auth_config = get_auth_config(integration)
        logger.info(f"-- Getting token for integration ID: {integration.id} Username: {auth_config.username} --")
        token = await client.get_token(
            base_url,
            auth_config.username,
            auth_config.password.get_secret_value(),
            auth_config.subscription_key.get_secret_value()
        )
    else:
        token = client.LoginResponse.parse_obj(saved_token)

    # Check if token is expired or about to expire in the next 5 minutes
    if datetime.now(timezone.utc) >= token.valid_to_utc - timedelta(minutes=5):
        if auth_config is None:
            auth_config = get_auth_config(integration)
        logger.info(f"-- Refreshing token for integration ID: {integration.id} --")
        try:
            token = await client.refresh_token(
                base_url,
                token.jwt,
                auth_config.subscription_key.get_secret_value()
            )
        except client.ForbiddenException:
            token = await client.get_token(
                base_url,
                auth_config.username,
                auth_config.password.get_secret_value(),
                auth_config.subscription_key.get_secret_value()
            )

    await state_manager.set_state(
        str(integration.id),
        "auth",
        {"jwt": token.jwt, "valid_to_utc": token.valid_to_utc.isoformat()},
        "token"
    )

    return token


async def action_auth(integration, action_config: AuthenticateConfig):
    logger.info(f"Executing 'auth' action with integration ID {integration.id} and action_config {action_config}...")

    try:
        logger.info(f"-- Getting token for integration ID: {integration.id} Username: {action_config.username} --")
        token_response = await client.get_token(
            CTC_BASE_URL,
            action_config.username,
            action_config.password.get_secret_value(),
            action_config.subscription_key.get_secret_value()
        )
        if token_response:
            token = (token_response.jwt[:MAX_TOKEN_DISPLAY_LENGTH] + '...') if len(token_response.jwt) > MAX_TOKEN_DISPLAY_LENGTH else token_response.jwt
            return {"valid_credentials": True, "token": token}
        logger.warning(f"-- Login failed for integration ID: {integration.id} Username: {action_config.username} --")
        return {"valid_credentials": False, "message": "Failed to retrieve token"}
    except client.UnauthorizedException as e:
        return {"valid_credentials": False, "status_code": e.status_code, "message": "Unauthorized access (bad username and/or password)"}
    except client.TooManyRequestsException as e:
        return {"status": "error", "status_code": 429, "message": "Ctrack Crystal API rate limit exceeded. Try again later."}
    except client.InternalServerException as e:
        return {"status": "error", "status_code": e.status_code, "message": "Internal server error at Ctrack Crystal"}
    except httpx.HTTPStatusError as e:
        return {"status": "error", "status_code": e.response.status_code, "message": str(e)}


@activity_logger()
@crontab_schedule("*/10 * * * *")
async def action_pull_observations(integration: Integration, action_config: PullObservationsConfig):
    logger.info(f"Executing 'pull_observations' action with integration ID {integration.id} and action_config {action_config}...")

    vehicles_processed = 0
    total_observations = 0
    base_url = integration.base_url or CTC_BASE_URL
    auth_config = get_auth_config(integration)

    try:
        token = await with_ctrack_semaphore(integration.id, retrieve_token(integration, base_url))

        logger.info(f"-- Getting vehicles for integration ID: {integration.id} --")
        vehicles_response = await with_ctrack_semaphore(
            integration.id,
            client.get_vehicles(token.jwt, auth_config.subscription_key.get_secret_value(), base_url),
        )

        if not vehicles_response:
            logger.warning(f"No valid vehicles found for integration ID {integration.id}, Username: {auth_config.username}")
            return {"status": "success", "vehicles_processed": 0, "observations_extracted": 0}

        logger.info(f"-- Extracted {len(vehicles_response.vehicles)} vehicles username: {auth_config.username}, Integration ID: {integration.id} --")

        for vehicle in vehicles_response.vehicles:
            logger.info(f"Fetching trips for vehicle {vehicle.id} to extract observations...")

            vehicle_last_updated: Optional[datetime] = None
            vehicle_state = await state_manager.get_state(
                integration_id=integration.id,
                action_id="pull_observations",
                source_id=vehicle.id,
            )
            vehicle_updated_at = vehicle_state.get("updated_at") if vehicle_state else None
            now = datetime.now(timezone.utc)
            min_filter_day = datetime.combine(
                (now - timedelta(days=MAX_PULL_LOOKBACK_DAYS)).date(),
                datetime.min.time(),
            ).replace(tzinfo=timezone.utc)
            if vehicle_updated_at:
                vehicle_last_updated = datetime.fromisoformat(vehicle_updated_at).replace(tzinfo=timezone.utc)
                filter_day = max(vehicle_last_updated, min_filter_day)
                filter_day = datetime.combine(filter_day.date(), datetime.min.time()).replace(tzinfo=timezone.utc)
                logger.info(f"Vehicle {vehicle.id} last processed at {vehicle_last_updated.isoformat()}. Fetching trips from {filter_day.date()} (capped at {MAX_PULL_LOOKBACK_DAYS} days lookback)...")
            else:
                filter_day = now - timedelta(days=1)
                logger.info(f"Vehicle {vehicle.id} has no last processed date. Fetching trips from yesterday...")

            parsed_config = PullVehicleTripsConfig(
                vehicle_id=vehicle.id,
                vehicle_serial_number=vehicle.serial_number,
                vehicle_display_name=vehicle.display_name,
                vehicle_last_updated=vehicle_last_updated,
                filter_day=filter_day,
                save_vehicle_state=True,
            )

            async def _fetch_this_vehicle():
                return await _fetch_one_vehicle_trips_observations(
                    token, auth_config, base_url, parsed_config
                )

            transformed_data, obs_count = await with_ctrack_semaphore(integration.id, _fetch_this_vehicle())

            if transformed_data:
                logger.info(
                    f"Extracted {len(transformed_data)} observations for vehicle {vehicle.id} from {filter_day.strftime('%Y-%m-%d')}"
                )
                for i, batch in enumerate(generate_batches(transformed_data, 200)):
                    logger.info(f"Sending observations batch #{i}: {len(batch)} observations. Vehicle: {vehicle.id}")
                    response = await send_observations_to_gundi(observations=batch, integration_id=integration.id)
                    total_observations += len(response)
                latest_time = max(transformed_data, key=lambda obs: obs["recorded_at"])["recorded_at"]
                await state_manager.set_state(
                    integration_id=integration.id,
                    action_id="pull_observations",
                    state={"updated_at": latest_time.isoformat()},
                    source_id=vehicle.id,
                )
            else:
                logger.info(f"No new observations to extract for vehicle {vehicle.id}")

            vehicles_processed += 1

        return {"status": "success", "vehicles_processed": vehicles_processed, "observations_extracted": total_observations}
    except client.TooManyRequestsException:
        logger.warning("Rate limit (429) from Ctrack Crystal API")
        raise
    except Exception as e:
        logger.error(f"Failed to process vehicles from integration ID {integration.id}, username: {auth_config.username}")
        raise e


@activity_logger()
async def action_trigger_fetch_vehicle_observations(integration, action_config: TriggerFetchVehicleObservationsConfig):
    logger.info(f"Executing 'trigger_fetch_vehicle_observations' action with integration ID {integration.id} and action_config {action_config}...")

    base_url = integration.base_url or CTC_BASE_URL
    auth_config = get_auth_config(integration)
    total_observations = 0

    try:
        token = await with_ctrack_semaphore(integration.id, retrieve_token(integration, base_url))
        vehicles_response = await with_ctrack_semaphore(
            integration.id,
            client.get_vehicles(token.jwt, auth_config.subscription_key.get_secret_value(), base_url),
        )

        if not vehicles_response:
            logger.error(f"No valid vehicles found for integration ID {integration.id}, Username: {auth_config.username}")
            return {"status": "error", "message": "There was an error while retrieving vehicles"}

        vehicle = next((v for v in vehicles_response.vehicles if v.id == action_config.vehicle_id), None)
        if not vehicle:
            logger.error(f"Vehicle {action_config.vehicle_id} not found for integration ID {integration.id}, Username: {auth_config.username}")
            return {"status": "error", "message": f"Vehicle {action_config.vehicle_id} not found"}

        for filter_day in date_range(action_config.start_date, action_config.end_date):
            logger.info(f"Fetching observations for vehicle {action_config.vehicle_id} on {filter_day}...")
            parsed_config = PullVehicleTripsConfig(
                vehicle_id=vehicle.id,
                vehicle_serial_number=vehicle.serial_number,
                vehicle_display_name=vehicle.display_name,
                filter_day=filter_day,
                save_vehicle_state=False,
            )

            async def _fetch_for_day():
                return await _fetch_one_vehicle_trips_observations(
                    token, auth_config, base_url, parsed_config
                )

            transformed_data, obs_count = await with_ctrack_semaphore(integration.id, _fetch_for_day())
            if transformed_data:
                for batch in generate_batches(transformed_data, 200):
                    response = await send_observations_to_gundi(observations=batch, integration_id=integration.id)
                    total_observations += len(response)

        return {"status": "success", "vehicle_triggered": True, "observations_extracted": total_observations}
    except client.TooManyRequestsException:
        logger.warning("Rate limit (429) from Ctrack Crystal API")
        return {"status": "error", "message": "API rate limit exceeded.", "status_code": 429}


@activity_logger()
async def action_fetch_vehicle_trips(integration, action_config: PullVehicleTripsConfig):
    logger.info(f"Executing 'action_fetch_vehicle_trips' action with integration ID {integration.id} and action_config {action_config}...")

    base_url = integration.base_url or CTC_BASE_URL
    auth_config = get_auth_config(integration)

    async def _do_fetch():
        token = await retrieve_token(integration, base_url)
        logger.info(f"-- Getting vehicle trips for integration ID: {integration.id} Vehicle ID: {action_config.vehicle_id} --")
        return await _fetch_one_vehicle_trips_observations(token, auth_config, base_url, action_config)

    try:
        transformed_data, _ = await with_ctrack_semaphore(integration.id, _do_fetch())

        if transformed_data:
            logger.info(f"Extracted {len(transformed_data)} observations for vehicle {action_config.vehicle_id} from {action_config.filter_day.strftime('%Y-%m-%d')}")
            observations_extracted = 0
            for i, batch in enumerate(generate_batches(transformed_data, 200)):
                logger.info(f"Sending observations batch #{i}: {len(batch)} observations. Vehicle: {action_config.vehicle_id}")
                response = await send_observations_to_gundi(observations=batch, integration_id=integration.id)
                observations_extracted += len(response)

            if action_config.save_vehicle_state:
                latest_time = max(transformed_data, key=lambda obs: obs["recorded_at"])["recorded_at"]
                await state_manager.set_state(
                    integration_id=integration.id,
                    action_id="pull_observations",
                    state={"updated_at": latest_time.isoformat()},
                    source_id=action_config.vehicle_id,
                )
            return {"observations_extracted": observations_extracted}
        else:
            logger.info(f"No new observations to extract for vehicle {action_config.vehicle_id}")
            return {"observations_extracted": 0}
    except client.TooManyRequestsException:
        message = f"Rate limit (429) from Ctrack Crystal API for vehicle {action_config.vehicle_id}"
        logger.warning(message)
        await log_action_activity(
            integration_id=integration.id,
            action_id="pull_observations",
            level=LogLevel.ERROR,
            title=f"Rate limit exceeded fetching trips for vehicle {action_config.vehicle_id}.",
            data={"message": message, "data": action_config}
        )
        return {"observations_extracted": 0}
    except Exception as e:
        message = f"Failed to fetch vehicle trips observations for vehicle {action_config.vehicle_id} from integration ID {integration.id}. Exception: {e}"
        logger.exception(message)
        await log_action_activity(
            integration_id=integration.id,
            action_id="pull_observations",
            level=LogLevel.ERROR,
            title=f"Failed to fetch trips observations for vehicle {action_config.vehicle_id}.",
            data={"message": message, "data": action_config}
        )
        return {"observations_extracted": 0}
