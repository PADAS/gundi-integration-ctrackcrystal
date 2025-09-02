import logging
import httpx

import app.actions.client as client

from gundi_core.schemas.v2 import LogLevel
from datetime import datetime, timedelta, timezone
from app.actions.configurations import AuthenticateConfig, PullObservationsConfig, PullVehicleTripsConfig, get_auth_config
from app.services.action_scheduler import trigger_action
from app.services.activity_logger import activity_logger, log_action_activity
from app.services.gundi import send_observations_to_gundi
from app.services.state import IntegrationStateManager
from app.services.utils import generate_batches


logger = logging.getLogger(__name__)
state_manager = IntegrationStateManager()


CTC_BASE_URL = "https://apim.ctrackcrystal.com/api"


def transform(observation, vehicle):
    additional_info = {
        key: value for key, value in observation.dict().items() if value and key not in ["eventTime", "latitude", "longitude"]
    }

    return {
        "source_name": vehicle.vehicle_display_name,
        "source": vehicle.vehicle_id,
        "type": "tracking-device",
        "subject_type": "vehicle",
        "recorded_at": observation.eventTime,
        "location": {
            "lat": observation.latitude,
            "lon": observation.longitude
        },
        "additional": {
            **additional_info
        }
    }

async def action_auth(integration, action_config: AuthenticateConfig):
    logger.info(
        f"Executing 'auth' action with integration ID {integration.id} and action_config {action_config}...")

    try:
        token_response = await client.get_token(
            integration.id,
            CTC_BASE_URL,
            action_config.username,
            action_config.password,
            action_config.subscription_key
        )
        if token_response:
            return {"valid_credentials": True, "token": token_response.jwt}
        return {"valid_credentials": False, "message": "Failed to retrieve token"}
    except client.CTCUnauthorizedException as e:
        return {"valid_credentials": False, "status_code": e.status_code, "message": "Unauthorized access (bad username and/or password)"}
    except client.CTCInternalServerException as e:
        return {"status": "error", "status_code": e.status_code, "message": "Internal server error at Ctrack Crystal"}
    except httpx.HTTPStatusError as e:
        return {"status": "error", "status_code": e.response.status_code, "message": str(e)}

@activity_logger()
async def action_pull_observations(integration, action_config: PullObservationsConfig):
    logger.info(f"Executing 'pull_observations' action with integration ID {integration.id} and action_config {action_config}...")

    vehicles_triggered = 0
    base_url = integration.base_url or CTC_BASE_URL

    auth_config = get_auth_config(integration)

    vehicles_response = await client.get_vehicles(integration, auth_config.subscription_key, base_url)

    if not vehicles_response:
        logger.warning(f"No valid vehicles found for integration ID {integration.id}, Username: {auth_config.username}")
        return {"status": "success", "vehicles_triggered": 0}

    try:
        for vehicle in vehicles_response.vehicles:
            logger.info(f"Triggering 'action_fetch_vehicle_trips' action for vehicle {vehicle.id} to extract observations...")

            parsed_config = PullVehicleTripsConfig(
                vehicle_id=vehicle.id,
                vehicle_serial_number=vehicle.serialNumber,
                vehicle_display_name=vehicle.displayName
            )
            await trigger_action(integration.id, "fetch_vehicle_trips", config=parsed_config)
            vehicles_triggered += 1

    except Exception as e:
        logger.error(f"Failed to process vehicles from integration ID {integration.id}, username: {auth_config.username}")
        raise e

    return {"status": "success", "vehicles_triggered": vehicles_triggered}


@activity_logger()
async def action_fetch_vehicle_trips(integration, action_config: PullVehicleTripsConfig):
    logger.info(f"Executing 'action_fetch_vehicle_trips' action with integration ID {integration.id} and action_config {action_config}...")

    base_url = integration.base_url or CTC_BASE_URL
    observations_extracted = 0
    auth_config = get_auth_config(integration)

    transformed_data = []

    # Get trips from today by default
    filter_day = datetime.now(timezone.utc) - timedelta(days=1)

    try:
        if trips_response := await client.get_vehicle_trips(
            integration,
            auth_config.subscription_key,
            base_url,
            action_config.vehicle_id,
            filter_day
        ):
            logger.info(f"Extracted {len(trips_response.payload)} trips for vehicle {action_config.vehicle_id} from {filter_day.strftime('%Y-%m-%d')}")
            # Check vehicle last processed time
            vehicle_last_updated = None
            if vehicle_state := await state_manager.get_state(
                integration_id=integration.id,
                action_id="pull_observations",
                source_id=action_config.vehicle_id
            ):
                vehicle_last_updated = datetime.fromisoformat(vehicle_state.get("updated_at")).replace(tzinfo=timezone.utc)

            for trip in trips_response.payload:
                for trip_detail in trip.details:
                    if trip_detail.tripId == "0":
                        logger.info(f"Skipping trip detail date {trip_detail.date} for vehicle {action_config.vehicle_id} (tripId is 0)")
                        continue

                    if vehicle_state:
                        if trip_detail.tripendTime <= vehicle_last_updated:
                            logger.info(f"Trip {trip_detail.tripId} for vehicle {action_config.vehicle_id} is already processed. Skipping...")
                            continue

                    logger.info(f"Getting trip summary for trip {trip_detail.tripId} vehicle {action_config.vehicle_id} to extract observations...")
                    if trip_summary := await client.get_trip_summary(
                        integration,
                        auth_config.subscription_key,
                        base_url,
                        action_config.vehicle_id,
                        trip_detail.tripId
                    ):
                        transformed_data.extend([transform(observation, action_config) for observation in trip_summary.locationSummary])

            if transformed_data:
                for i, batch in enumerate(generate_batches(transformed_data, 200)):
                    logger.info(f'Sending observations batch #{i}: {len(batch)} observations. Vehicle: {action_config.vehicle_id}')
                    response = await send_observations_to_gundi(observations=batch, integration_id=integration.id)
                    observations_extracted += len(response)

                # Save latest device updated_at
                latest_time = max(transformed_data, key=lambda obs: obs["recorded_at"])["recorded_at"]
                state = {"updated_at": latest_time.strftime("%Y-%m-%dT%H:%M:%S")}

                await state_manager.set_state(
                    integration_id=integration.id,
                    action_id="pull_observations",
                    state=state,
                    source_id=action_config.vehicle_id
                )

                return {"observations_extracted": observations_extracted}
            else:
                logger.info(f"No new observations to extract for vehicle {action_config.vehicle_id}")
                return {"observations_extracted": 0}
        else:
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
