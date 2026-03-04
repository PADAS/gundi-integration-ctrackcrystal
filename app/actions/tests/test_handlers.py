import pytest
import pydantic
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

import app.actions.handlers as handlers
import app.datasource.ctrack as client
from app.actions.configurations import (
    AuthenticateConfig,
    PullObservationsConfig,
    PullVehicleTripsConfig,
    TriggerFetchVehicleObservationsConfig
)


@pytest.mark.asyncio
async def test_action_auth_success(mocker):
    integration = MagicMock()
    integration.id = "integration_id"
    action_config = AuthenticateConfig(username="user", password=pydantic.SecretStr("pass"), subscription_key=pydantic.SecretStr("key"))

    mock_token = MagicMock()
    mock_token.jwt = "token_jwt"

    mock_get_token = mocker.patch("app.datasource.ctrack.get_token", return_value=mock_token)

    result = await handlers.action_auth(integration, action_config)

    mock_get_token.assert_awaited_once_with(
        handlers.CTC_BASE_URL,
        action_config.username,
        action_config.password.get_secret_value(),
        action_config.subscription_key.get_secret_value(),
    )
    assert result == {"valid_credentials": True, "token": "token_jwt"}


@pytest.mark.asyncio
async def test_action_auth_unauthorized(mocker):
    integration = MagicMock()
    integration.id = "integration_id"
    action_config = AuthenticateConfig(username="user", password=pydantic.SecretStr("pass"), subscription_key=pydantic.SecretStr("key"))

    mocker.patch(
        "app.datasource.ctrack.get_token",
        side_effect=handlers.client.UnauthorizedException("Unauthorized", status_code=401),
    )

    result = await handlers.action_auth(integration, action_config)

    assert result["valid_credentials"] is False
    assert result["status_code"] == 401
    assert "Unauthorized" in result["message"]


@pytest.mark.asyncio
async def test_action_auth_rate_limit_429(mocker):
    integration = MagicMock()
    integration.id = "integration_id"
    action_config = AuthenticateConfig(username="user", password=pydantic.SecretStr("pass"), subscription_key=pydantic.SecretStr("key"))

    mocker.patch(
        "app.datasource.ctrack.get_token",
        side_effect=client.TooManyRequestsException("Rate Limit reached", None),
    )

    result = await handlers.action_auth(integration, action_config)

    assert result["status"] == "error"
    assert result["status_code"] == 429
    assert "rate limit" in result["message"].lower()


@pytest.mark.asyncio
async def test_action_pull_observations_429_reraises(mocker, mock_publish_event):
    integration = MagicMock()
    integration.id = "int1"
    integration.base_url = None

    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")
    auth_config.username = "user"
    auth_config.password = pydantic.SecretStr("pass")

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)

    mocker.patch(
        "app.actions.handlers.retrieve_token",
        side_effect=client.TooManyRequestsException("Rate Limit reached", None),
    )

    with pytest.raises(client.TooManyRequestsException):
        await handlers.action_pull_observations(integration, PullObservationsConfig())


@pytest.mark.asyncio
async def test_action_pull_observations_fetches_vehicle_trips_inline(mocker, mock_publish_event):
    integration = MagicMock()
    integration.id = "int1"
    integration.base_url = None

    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")
    auth_config.username = "user"
    auth_config.password = pydantic.SecretStr("pass")

    mock_token = MagicMock()
    mock_token.jwt = "token_jwt"
    mock_token.valid_to_utc = datetime.now(timezone.utc) + timedelta(hours=1)

    mocker.patch("app.datasource.ctrack.get_token", new_callable=AsyncMock, return_value=mock_token)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.actions.handlers.state_manager.set_state", new_callable=AsyncMock)

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    vehicles_response = MagicMock(vehicles=[client.Vehicle(id="veh1", serial_number="sn1", display_name="Vehicle 1")])
    mocker.patch("app.datasource.ctrack.get_vehicles", new_callable=AsyncMock, return_value=vehicles_response)
    one_obs = [{"recorded_at": datetime.now(timezone.utc), "source": "veh1", "source_name": "Vehicle 1"}]
    mocker.patch(
        "app.actions.handlers._fetch_one_vehicle_trips_observations",
        new_callable=AsyncMock,
        return_value=(one_obs, 1),
    )
    mocker.patch("app.actions.handlers.send_observations_to_gundi", new_callable=AsyncMock, return_value=[1])

    result = await handlers.action_pull_observations(integration, PullObservationsConfig())

    assert result["status"] == "success"
    assert result["vehicles_processed"] == 1
    # With multi-day catchup, a vehicle with no prior state processes yesterday + today (2 days)
    assert result["observations_extracted"] == 2


@pytest.mark.asyncio
async def test_action_trigger_fetch_vehicle_observations_fetches_inline(mocker, mock_publish_event):
    integration = MagicMock()
    integration.id = "int1"
    integration.base_url = None

    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")
    auth_config.username = "user"
    auth_config.password = pydantic.SecretStr("pass")

    today = datetime.now(timezone.utc).date()
    action_config = TriggerFetchVehicleObservationsConfig(
        start_date=today,
        end_date=today,
        vehicle_id="veh1"
    )

    mock_token = MagicMock()
    mock_token.jwt = "token_jwt"
    mock_token.valid_to_utc = datetime.now(timezone.utc) + timedelta(hours=1)

    mocker.patch("app.datasource.ctrack.get_token", new_callable=AsyncMock, return_value=mock_token)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.actions.handlers.state_manager.set_state", new_callable=AsyncMock)

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    vehicles_response = MagicMock(vehicles=[client.Vehicle(id="veh1", serial_number="sn1", display_name="Vehicle 1")])
    mocker.patch("app.datasource.ctrack.get_vehicles", new_callable=AsyncMock, return_value=vehicles_response)
    one_obs = [{"recorded_at": datetime.now(timezone.utc)}]
    mocker.patch(
        "app.actions.handlers._fetch_one_vehicle_trips_observations",
        new_callable=AsyncMock,
        return_value=(one_obs, 1),
    )
    mocker.patch("app.actions.handlers.send_observations_to_gundi", new_callable=AsyncMock, return_value=[1])

    result = await handlers.action_trigger_fetch_vehicle_observations(integration, action_config)

    assert result["status"] == "success"
    assert result["vehicle_triggered"] is True
    assert result["observations_extracted"] == 1


@pytest.mark.asyncio
async def test_action_trigger_fetch_vehicle_observations_429(mocker, mock_publish_event):
    integration = MagicMock()
    integration.id = "int1"
    integration.base_url = None

    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")
    auth_config.username = "user"
    auth_config.password = pydantic.SecretStr("pass")

    action_config = TriggerFetchVehicleObservationsConfig(
        start_date=datetime.now(timezone.utc).date() - timedelta(days=1),
        end_date=datetime.now(timezone.utc).date(),
        vehicle_id="veh1"
    )

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)

    mocker.patch(
        "app.actions.handlers.retrieve_token",
        side_effect=client.TooManyRequestsException("Rate Limit reached", None),
    )

    result = await handlers.action_trigger_fetch_vehicle_observations(integration, action_config)

    assert result["status"] == "error"
    assert result["status_code"] == 429
    assert "rate limit" in result["message"].lower()


@pytest.mark.asyncio
async def test_action_pull_observations_no_vehicles(mocker, mock_publish_event):
    integration = MagicMock()
    integration.id = "integration_id"
    integration.base_url = None

    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")
    auth_config.username = "user"
    auth_config.password = pydantic.SecretStr("pass")

    mock_token = MagicMock()
    mock_token.jwt = "token_jwt"
    mock_token.valid_to_utc = datetime.now(timezone.utc) + timedelta(hours=1)

    mocker.patch("app.datasource.ctrack.get_token", new_callable=AsyncMock, return_value=mock_token)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)
    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mocker.patch("app.datasource.ctrack.get_vehicles", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.actions.handlers.state_manager.set_state", new_callable=AsyncMock)

    result = await handlers.action_pull_observations(integration, PullObservationsConfig())

    assert result["status"] == "success"
    assert result["vehicles_processed"] == 0
    assert result["observations_extracted"] == 0


@pytest.mark.asyncio
async def test_action_fetch_vehicle_trips_success(mocker, mock_publish_event):
    integration = MagicMock()
    integration.id = "integration_id"
    integration.base_url = None

    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")
    auth_config.username = "user"
    auth_config.password = pydantic.SecretStr("pass")

    mock_token = MagicMock()
    mock_token.jwt = "token_jwt"
    mock_token.valid_to_utc = datetime.now(timezone.utc) + timedelta(hours=1)

    mocker.patch("app.datasource.ctrack.get_token", new_callable=AsyncMock, return_value=mock_token)

    vehicle_id = "veh1"
    action_config = PullVehicleTripsConfig(
        vehicle_id=vehicle_id,
        vehicle_serial_number="sn1",
        vehicle_display_name="Vehicle 1",
        filter_day=datetime.now(timezone.utc)
    )

    trips_payload = [
        AsyncMock(
            details=[
                AsyncMock(tripId="1", tripendTime=datetime.now(timezone.utc) + timedelta(minutes=10), date="2023-01-01")
            ]
        )
    ]
    trips_response = AsyncMock(payload=trips_payload)

    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mock_get_vehicle_trips = mocker.patch(
        "app.datasource.ctrack.get_vehicle_trips",
        new_callable=AsyncMock,
        return_value=trips_response
    )
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mock_get_trip_summary = mocker.patch(
        "app.datasource.ctrack.get_trip_summary",
        new_callable=AsyncMock,
        return_value=client.DetailedTripSummaryResponse(locationSummary=[client.LocationSummary(latitude=1.0, longitude=2.0, event_time=datetime.now(timezone.utc))])
    )
    mock_send_observations = mocker.patch("app.actions.handlers.send_observations_to_gundi", new_callable=AsyncMock, return_value=[1])
    mock_set_state = mocker.patch("app.actions.handlers.state_manager.set_state", new_callable=AsyncMock)

    result = await handlers.action_fetch_vehicle_trips(integration, action_config)

    assert result["observations_extracted"] == 1
    mock_get_vehicle_trips.assert_awaited_once()
    mock_get_trip_summary.assert_awaited()
    mock_send_observations.assert_awaited()
    mock_set_state.assert_awaited()


@pytest.mark.asyncio
async def test_action_fetch_vehicle_trips_exception(mocker, mock_publish_event):
    integration = AsyncMock()
    integration.id = "integration_id"
    integration.base_url = None
    auth_config = AsyncMock()
    auth_config.subscription_key = "key"

    vehicle_id = "veh1"
    action_config = PullVehicleTripsConfig(
        vehicle_id=vehicle_id,
        vehicle_serial_number="sn1",
        vehicle_display_name="Vehicle 1",
        filter_day=datetime.now(timezone.utc)
    )

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mocker.patch("app.datasource.ctrack.get_vehicle_trips", new_callable=AsyncMock, side_effect=Exception("fail"))
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)

    mock_log_action_activity = mocker.patch("app.actions.handlers.log_action_activity", new_callable=AsyncMock)

    result = await handlers.action_fetch_vehicle_trips(integration, action_config)

    assert result["observations_extracted"] == 0
    mock_log_action_activity.assert_awaited()


@pytest.mark.asyncio
async def test_action_fetch_vehicle_trips_429(mocker, mock_publish_event):
    integration = MagicMock()
    integration.id = "integration_id"
    integration.base_url = None
    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")

    vehicle_id = "veh1"
    action_config = PullVehicleTripsConfig(
        vehicle_id=vehicle_id,
        vehicle_serial_number="sn1",
        vehicle_display_name="Vehicle 1",
        filter_day=datetime.now(timezone.utc)
    )

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.actions.handlers.state_manager.set_state", new_callable=AsyncMock)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)
    mocker.patch(
        "app.actions.handlers.client.get_vehicle_trips",
        new_callable=AsyncMock,
        side_effect=client.TooManyRequestsException("Rate Limit reached", None),
    )
    mock_token = MagicMock(jwt="token", valid_to_utc=datetime.now(timezone.utc) + timedelta(hours=1))
    mocker.patch("app.actions.handlers.retrieve_token", new_callable=AsyncMock, return_value=mock_token)

    mock_log_action_activity = mocker.patch("app.actions.handlers.log_action_activity", new_callable=AsyncMock)

    result = await handlers.action_fetch_vehicle_trips(integration, action_config)

    assert result["observations_extracted"] == 0
    mock_log_action_activity.assert_awaited_once()
    kwargs = mock_log_action_activity.call_args[1]
    assert "rate limit" in kwargs.get("title", "").lower()
