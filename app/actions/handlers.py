import asyncio
import logging
import httpx
from app.datasource import ctrackcrystal

from datetime import date, datetime, timedelta, timezone
from typing import AsyncGenerator, Dict, List, Optional, Tuple

from gundi_core.schemas.v2 import LogLevel, Integration
from app.actions.configurations import (
    AuthenticateConfig,
    PullObservationsConfig,
    PullVehicleTripsConfig,
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



INVALID_TRIP_ID = "0"
MAX_TOKEN_DISPLAY_LENGTH = 100
MAX_PULL_LOOKBACK_DAYS = 3
PROCESSED_TRIPS_MAX_AGE_DAYS = 14


def _prune_processed_trips(
    processed_trips: Dict[str, datetime],
    max_age_days: int = PROCESSED_TRIPS_MAX_AGE_DAYS,
    now: Optional[datetime] = None,
) -> Dict[str, datetime]:
    """Return a copy with only entries whose trip_end_time is within the last max_age_days."""
    if not processed_trips:
        return {}
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=max_age_days)
    return {trip_id: t for trip_id, t in processed_trips.items() if t >= cutoff}


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


def transform(observation: ctrackcrystal.LocationSummary, vehicle: PullVehicleTripsConfig) -> dict:
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
    token: ctrackcrystal.LoginResponse,
    auth_config: AuthenticateConfig,
    base_url: str,
    action_config: PullVehicleTripsConfig,
    integration_id: str = "",
    processed_trips: Optional[Dict[str, datetime]] = None,
) -> AsyncGenerator[ctrackcrystal.LocationSummary, None]:
    """
    Fetch trips and trip summaries for one vehicle/filter_day; yield each observation (LocationSummary).
    Caller should transform yielded observations to the Gundi model. Does not send to Gundi or save state.
    Caller must hold Ctrack semaphore if limiting concurrency.
    If processed_trips (mutable dict) is passed, trips already in it with stored trip_end_time >= current are skipped,
    and each fetched trip is recorded as processed_trips[trip_id] = trip_end_time.
    Raises ctrackcrystal.TooManyRequestsException on 429.
    """
    trips_response = await ctrackcrystal.get_trips(
        base_url,
        token.jwt,
        auth_config.subscription_key.get_secret_value(),
        [action_config.vehicle_id],
        action_config.filter_day.date(),
    )
    if not trips_response:
        logger.warning(
            f"No trips response returned for vehicle {action_config.vehicle_id} on {action_config.filter_day.date()}"
        )
        return

    for trip in trips_response.payload:
        for trip_detail in trip.details:
            '''
            Skip trips with an invalid trip ID.
            
            Skip trips that are already in the processed_trips dictionary.
            '''
            # Skip trips with an invalid trip ID.

            if trip_detail.trip_id == INVALID_TRIP_ID:
                logger.info(
                    f"Skipping trip detail date {trip_detail.date} for vehicle {action_config.vehicle_id} (tripId is 0)"
                )
                continue

            # Skip trips that are already processed.
            if processed_trips is not None and trip_detail.trip_id in processed_trips and trip_detail.trip_end_time is not None:
                stored = processed_trips[trip_detail.trip_id]
                if stored >= trip_detail.trip_end_time:
                    logger.info(
                        f"Trip {trip_detail.trip_id} for vehicle {action_config.vehicle_id} already in processed_trips. Skipping DetailedTripSummary..."
                    )
                    continue

            logger.info(
                f"Getting trip summary for trip {trip_detail.trip_id} vehicle {action_config.vehicle_id} to extract observations..."
            )
            trip_summary = await ctrackcrystal.get_detailed_trip_summary(
                base_url,
                token.jwt,
                auth_config.subscription_key.get_secret_value(),
                trip_detail.trip_id,
            )
            if trip_summary:
                for observation in trip_summary.location_summary:
                    yield observation
                if processed_trips is not None and trip_detail.trip_end_time is not None:
                    processed_trips[trip_detail.trip_id] = trip_detail.trip_end_time
            else:
                logger.warning(
                    f"-- No trip summary returned for trip {trip_detail.trip_id} Vehicle ID {action_config.vehicle_id} --"
                )
                if integration_id:
                    await log_action_activity(
                        integration_id=integration_id,
                        action_id="pull_observations",
                        title=f"Trip {trip_detail.trip_id}: no location data returned",
                        level=LogLevel.WARNING,
                        data={"vehicle_id": action_config.vehicle_id, "trip_id": trip_detail.trip_id},
                    )


async def retrieve_token(integration: Integration, base_url: str) -> ctrackcrystal.LoginResponse:
    """
    Helper function to retrieve token from state or CTC API.
    May raise ctrackcrystal.TooManyRequestsException after retries if the API returns 429.
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
        token = await ctrackcrystal.login(
            base_url,
            auth_config.username,
            auth_config.password.get_secret_value(),
            auth_config.subscription_key.get_secret_value()
        )
        if token is None:
            raise RuntimeError("Failed to obtain token (check credentials).")
    else:
        token = ctrackcrystal.LoginResponse.parse_obj(saved_token)

    # Check if token is expired or about to expire in the next 5 minutes
    if datetime.now(timezone.utc) >= token.valid_to_utc - timedelta(minutes=5):
        if auth_config is None:
            auth_config = get_auth_config(integration)
        logger.info(f"-- Refreshing token for integration ID: {integration.id} --")
        try:
            new_token = await ctrackcrystal.refresh_token(
                base_url,
                token.jwt,
                auth_config.subscription_key.get_secret_value()
            )
            if new_token is not None:
                token = new_token
            # else keep existing token and re-save below
        except ctrackcrystal.ForbiddenException:
            token = await ctrackcrystal.login(
                base_url,
                auth_config.username,
                auth_config.password.get_secret_value(),
                auth_config.subscription_key.get_secret_value()
            )
            if token is None:
                raise RuntimeError("Failed to obtain token after refresh (check credentials).")

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
        token_response = await ctrackcrystal.login(
            ctrackcrystal.BASE_URL,
            action_config.username,
            action_config.password.get_secret_value(),
            action_config.subscription_key.get_secret_value()
        )
        if token_response:
            token = (token_response.jwt[:MAX_TOKEN_DISPLAY_LENGTH] + '...') if len(token_response.jwt) > MAX_TOKEN_DISPLAY_LENGTH else token_response.jwt
            return {"valid_credentials": True, "token": token}
        logger.warning(f"-- Login failed for integration ID: {integration.id} Username: {action_config.username} --")
        return {"valid_credentials": False, "message": "Failed to retrieve token"}
    except ctrackcrystal.UnauthorizedException as e:
        return {"valid_credentials": False, "status_code": e.status_code, "message": "Unauthorized access (bad username and/or password)"}
    except ctrackcrystal.TooManyRequestsException as e:
        return {"status": "error", "status_code": 429, "message": "Ctrack Crystal API rate limit exceeded. Try again later."}
    except ctrackcrystal.InternalServerException as e:
        return {"status": "error", "status_code": e.status_code, "message": "Internal server error at Ctrack Crystal"}
    except httpx.HTTPStatusError as e:
        return {"status": "error", "status_code": e.response.status_code, "message": str(e)}


@activity_logger()
@crontab_schedule("*/10 * * * *")
async def action_pull_observations(integration: Integration, action_config: PullObservationsConfig):
    logger.info(f"Executing 'pull_observations' action with integration ID {integration.id} and action_config {action_config}...")

    vehicles_processed = 0
    vehicles_failed = 0
    total_observations = 0
    base_url = integration.base_url or ctrackcrystal.BASE_URL
    auth_config = get_auth_config(integration)

    try:
        token = await with_ctrack_semaphore(integration.id, retrieve_token(integration, base_url))

        logger.info(f"-- Getting vehicles for integration ID: {integration.id} --")
        vehicles_response = await with_ctrack_semaphore(
            integration.id,
            ctrackcrystal.get_vehicles(base_url, token.jwt, auth_config.subscription_key.get_secret_value()),
        )

        if not vehicles_response:
            logger.warning(f"No valid vehicles found for integration ID {integration.id}, Username: {auth_config.username}")
            return {"status": "success", "vehicles_processed": 0, "observations_extracted": 0}

        logger.info(f"-- Extracted {len(vehicles_response.vehicles)} vehicles username: {auth_config.username}, Integration ID: {integration.id} --")

        # Location 1: Log vehicle count after fetching
        await log_action_activity(
            integration_id=str(integration.id),
            action_id="pull_observations",
            title=f"Found {len(vehicles_response.vehicles)} vehicles to process",
            level=LogLevel.INFO,
        )

        for vehicle in vehicles_response.vehicles:
            try:
                logger.info(f"Fetching trips for vehicle {vehicle.id} to extract observations...")

                vehicle_state = await state_manager.get_state(
                    integration_id=integration.id,
                    action_id="pull_observations",
                    source_id=vehicle.id,
                )
                vehicle_updated_at = vehicle_state.get("updated_at") if vehicle_state else None
                raw_processed = vehicle_state.get("processed_trips", {}) if vehicle_state else {}
                processed_trips: Dict[str, datetime] = {}
                for tid, tstr in raw_processed.items():
                    try:
                        t = datetime.fromisoformat(tstr).replace(tzinfo=timezone.utc)
                        processed_trips[tid] = t
                    except (TypeError, ValueError):
                        pass
                now = datetime.now(timezone.utc)
                min_filter_day = datetime.combine(
                    (now - timedelta(days=MAX_PULL_LOOKBACK_DAYS)).date(),
                    datetime.min.time(),
                ).replace(tzinfo=timezone.utc)
                today = datetime.combine(now.date(), datetime.min.time()).replace(tzinfo=timezone.utc)

                if vehicle_updated_at:
                    last_updated = datetime.fromisoformat(vehicle_updated_at).replace(tzinfo=timezone.utc)
                    start_filter_day = max(last_updated, min_filter_day)
                    start_filter_day = datetime.combine(start_filter_day.date(), datetime.min.time()).replace(tzinfo=timezone.utc)
                    logger.info(f"Vehicle {vehicle.id} last updated at {last_updated.isoformat()}. Fetching trips from {start_filter_day.date()} to {today.date()} (capped at {MAX_PULL_LOOKBACK_DAYS} days lookback)...")
                else:
                    start_filter_day = now - timedelta(days=1)
                    start_filter_day = datetime.combine(start_filter_day.date(), datetime.min.time()).replace(tzinfo=timezone.utc)
                    logger.info(f"Vehicle {vehicle.id} has no last updated date. Fetching trips from yesterday...")

                # Multi-day catchup — loop through all days from start_filter_day to today
                vehicle_obs_count = 0
                for filter_day in date_range(start_filter_day.date(), today.date()):
                    parsed_config = PullVehicleTripsConfig(
                        vehicle_id=vehicle.id,
                        vehicle_serial_number=vehicle.serial_number,
                        vehicle_display_name=vehicle.display_name,
                        filter_day=filter_day,
                        save_vehicle_state=True,
                    )

                    async def _fetch_this_vehicle():
                        transformed = []
                        async for observation in _fetch_one_vehicle_trips_observations(
                            token, auth_config, base_url, parsed_config,
                            integration_id=str(integration.id),
                            processed_trips=processed_trips,
                        ):
                            transformed.append(transform(observation, parsed_config))
                        return transformed

                    transformed_data = await with_ctrack_semaphore(integration.id, _fetch_this_vehicle())

                    if transformed_data:
                        logger.info(
                            f"Extracted {len(transformed_data)} observations for vehicle {vehicle.id} from {filter_day.strftime('%Y-%m-%d')}"
                        )
                        for i, batch in enumerate(generate_batches(transformed_data, 200)):
                            logger.info(f"Sending observations batch #{i}: {len(batch)} observations. Vehicle: {vehicle.id}")
                            response = await send_observations_to_gundi(observations=batch, integration_id=integration.id)
                            total_observations += len(response)
                            vehicle_obs_count += len(response)
                        latest_time = max(transformed_data, key=lambda obs: obs["recorded_at"])["recorded_at"]
                        pruned = _prune_processed_trips(processed_trips, now=now)
                        await state_manager.set_state(
                            integration_id=integration.id,
                            action_id="pull_observations",
                            state={
                                "updated_at": latest_time.isoformat(),
                                "processed_trips": {k: v.isoformat() for k, v in pruned.items()},
                            },
                            source_id=vehicle.id,
                        )
                    else:
                        logger.info(f"No new observations for vehicle {vehicle.id} on {filter_day.date()}")
                        # Advance state to this day so next run knows we've considered it
                        pruned = _prune_processed_trips(processed_trips, now=now)
                        await state_manager.set_state(
                            integration_id=integration.id,
                            action_id="pull_observations",
                            state={
                                "updated_at": filter_day.isoformat(),
                                "processed_trips": {k: v.isoformat() for k, v in pruned.items()},
                            },
                            source_id=vehicle.id,
                        )

                vehicles_processed += 1

                # Location 2: Per-vehicle results
                await log_action_activity(
                    integration_id=str(integration.id),
                    action_id="pull_observations",
                    title=f"Vehicle {vehicle.id}: {vehicle_obs_count} observations from {start_filter_day.date()} to {today.date()}",
                    level=LogLevel.INFO,
                    data={"vehicle_id": vehicle.id, "start_day": str(start_filter_day.date()), "end_day": str(today.date()), "observations": vehicle_obs_count},
                )

            # Fix B: Per-vehicle exception isolation
            except ctrackcrystal.TooManyRequestsException:
                # Re-raise rate limits — these affect all vehicles, not just this one
                raise
            except Exception as e:
                vehicles_failed += 1
                logger.exception(f"Failed to process vehicle {vehicle.id} from integration ID {integration.id}: {e}")
                await log_action_activity(
                    integration_id=str(integration.id),
                    action_id="pull_observations",
                    title=f"Vehicle {vehicle.id}: processing failed",
                    level=LogLevel.ERROR,
                    data={"vehicle_id": vehicle.id, "error": str(e)},
                )

        # Location 3: End-of-action summary
        await log_action_activity(
            integration_id=str(integration.id),
            action_id="pull_observations",
            title=f"Completed: {vehicles_processed} vehicles, {total_observations} observations" + (f", {vehicles_failed} failed" if vehicles_failed else ""),
            level=LogLevel.INFO,
            data={"vehicles_processed": vehicles_processed, "vehicles_failed": vehicles_failed, "observations_extracted": total_observations},
        )

        return {"status": "success", "vehicles_processed": vehicles_processed, "vehicles_failed": vehicles_failed, "observations_extracted": total_observations}
    except ctrackcrystal.TooManyRequestsException:
        logger.warning("Rate limit (429) from Ctrack Crystal API")
        raise
    except (ctrackcrystal.UnauthorizedException, ctrackcrystal.ForbiddenException) as e:
        logger.error(f"Authentication failed for integration ID {integration.id}, username: {auth_config.username}: {e}")
        await log_action_activity(
            integration_id=str(integration.id),
            action_id="pull_observations",
            title="Authentication failed: check credentials in the portal",
            level=LogLevel.ERROR,
            data={"error": str(e), "username": auth_config.username},
        )
        raise
    except Exception as e:
        logger.error(f"Failed to process vehicles from integration ID {integration.id}, username: {auth_config.username}")
        raise e


@activity_logger()
async def action_fetch_vehicle_trips(integration, action_config: PullVehicleTripsConfig):
    logger.info(f"Executing 'action_fetch_vehicle_trips' action with integration ID {integration.id} and action_config {action_config}...")

    base_url = integration.base_url or ctrackcrystal.BASE_URL
    auth_config = get_auth_config(integration)

    vehicle_state = await state_manager.get_state(
        integration_id=integration.id,
        action_id="pull_observations",
        source_id=action_config.vehicle_id,
    )
    raw_processed = vehicle_state.get("processed_trips", {}) if vehicle_state else {}
    processed_trips: Dict[str, datetime] = {}
    for tid, tstr in raw_processed.items():
        try:
            t = datetime.fromisoformat(tstr).replace(tzinfo=timezone.utc)
            processed_trips[tid] = t
        except (TypeError, ValueError):
            pass

    async def _do_fetch():
        token = await retrieve_token(integration, base_url)
        logger.info(f"-- Getting vehicle trips for integration ID: {integration.id} Vehicle ID: {action_config.vehicle_id} --")
        transformed = []
        async for observation in _fetch_one_vehicle_trips_observations(
            token, auth_config, base_url, action_config, integration_id=str(integration.id),
            processed_trips=processed_trips,
        ):
            transformed.append(transform(observation, action_config))
        return transformed

    try:
        transformed_data = await with_ctrack_semaphore(integration.id, _do_fetch())

        if transformed_data:
            logger.info(f"Extracted {len(transformed_data)} observations for vehicle {action_config.vehicle_id} from {action_config.filter_day.strftime('%Y-%m-%d')}")
            observations_extracted = 0
            for i, batch in enumerate(generate_batches(transformed_data, 200)):
                logger.info(f"Sending observations batch #{i}: {len(batch)} observations. Vehicle: {action_config.vehicle_id}")
                response = await send_observations_to_gundi(observations=batch, integration_id=integration.id)
                observations_extracted += len(response)

            if action_config.save_vehicle_state:
                latest_time = max(transformed_data, key=lambda obs: obs["recorded_at"])["recorded_at"]
                pruned = _prune_processed_trips(processed_trips)
                await state_manager.set_state(
                    integration_id=integration.id,
                    action_id="pull_observations",
                    state={
                        "updated_at": latest_time.isoformat(),
                        "processed_trips": {k: v.isoformat() for k, v in pruned.items()},
                    },
                    source_id=action_config.vehicle_id,
                )
            return {"observations_extracted": observations_extracted}
        else:
            logger.info(f"No new observations to extract for vehicle {action_config.vehicle_id}")
            return {"observations_extracted": 0}
    except ctrackcrystal.TooManyRequestsException:
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
    except (ctrackcrystal.UnauthorizedException, ctrackcrystal.ForbiddenException) as e:
        logger.error(f"Authentication failed for integration ID {integration.id}: {e}")
        await log_action_activity(
            integration_id=integration.id,
            action_id="pull_observations",
            level=LogLevel.ERROR,
            title="Authentication failed: check credentials in the portal",
            data={"error": str(e)},
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
