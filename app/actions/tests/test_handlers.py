import pytest
import pydantic
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, timedelta

import app.actions.handlers as handlers
from app.datasource import ctrackcrystal
from app.actions.configurations import (
    AuthenticateConfig,
    PullObservationsConfig,
    PullVehicleTripsConfig
)


def test_prune_processed_trips():
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=20)
    recent = now - timedelta(days=5)
    processed = {"t1": old, "t2": recent}
    pruned = handlers._prune_processed_trips(processed, max_age_days=14, now=now)
    assert list(pruned.keys()) == ["t2"]
    assert pruned["t2"] == recent
    empty = handlers._prune_processed_trips({}, max_age_days=14, now=now)
    assert empty == {}


@pytest.mark.asyncio
async def test_action_auth_success(mocker):
    integration = MagicMock()
    integration.id = "integration_id"
    action_config = AuthenticateConfig(username="user", password=pydantic.SecretStr("pass"), subscription_key=pydantic.SecretStr("key"))

    mock_token = MagicMock()
    mock_token.jwt = "token_jwt"

    mock_get_token = mocker.patch("app.datasource.ctrackcrystal.login", return_value=mock_token)

    result = await handlers.action_auth(integration, action_config)

    mock_get_token.assert_awaited_once_with(
        ctrackcrystal.BASE_URL,
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
        "app.datasource.ctrackcrystal.login",
        side_effect=handlers.ctrackcrystal.UnauthorizedException("Unauthorized", status_code=401),
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
        "app.datasource.ctrackcrystal.login",
        side_effect=ctrackcrystal.TooManyRequestsException("Rate Limit reached", None),
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
        side_effect=ctrackcrystal.TooManyRequestsException("Rate Limit reached", None),
    )

    with pytest.raises(ctrackcrystal.TooManyRequestsException):
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

    mocker.patch("app.datasource.ctrackcrystal.login", new_callable=AsyncMock, return_value=mock_token)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mocker.patch("app.actions.handlers.state_manager.set_state", new_callable=AsyncMock)

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    vehicles_response = MagicMock(vehicles=[ctrackcrystal.Vehicle(id="veh1", serial_number="sn1", display_name="Vehicle 1")])
    mocker.patch("app.datasource.ctrackcrystal.get_vehicles", new_callable=AsyncMock, return_value=vehicles_response)

    async def _mock_observations_gen():
        yield ctrackcrystal.LocationSummary(
            event_time=datetime.now(timezone.utc),
            latitude=1.0,
            longitude=2.0,
        )

    mocker.patch(
        "app.actions.handlers._fetch_one_vehicle_trips_observations",
        side_effect=lambda *args, **kwargs: _mock_observations_gen(),
    )
    mocker.patch("app.actions.handlers.send_observations_to_gundi", new_callable=AsyncMock, return_value=[1])

    result = await handlers.action_pull_observations(integration, PullObservationsConfig())

    assert result["status"] == "success"
    assert result["vehicles_processed"] == 1
    # With multi-day catchup, a vehicle with no prior state processes yesterday + today (2 days)
    assert result["observations_extracted"] == 2



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

    mocker.patch("app.datasource.ctrackcrystal.login", new_callable=AsyncMock, return_value=mock_token)
    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)
    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mocker.patch("app.datasource.ctrackcrystal.get_vehicles", new_callable=AsyncMock, return_value=None)
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

    mocker.patch("app.datasource.ctrackcrystal.login", new_callable=AsyncMock, return_value=mock_token)

    vehicle_id = "veh1"
    action_config = PullVehicleTripsConfig(
        vehicle_id=vehicle_id,
        vehicle_serial_number="sn1",
        vehicle_display_name="Vehicle 1",
        filter_day=datetime.now(timezone.utc)
    )

    trip_end_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    trip_detail = MagicMock(trip_id="1", trip_end_time=trip_end_time, date=datetime.now(timezone.utc))
    trips_payload = [MagicMock(details=[trip_detail])]
    trips_response = MagicMock(payload=trips_payload)

    mocker.patch("app.services.activity_logger.publish_event", mock_publish_event)
    mocker.patch("app.services.action_runner.publish_event", mock_publish_event)
    mocker.patch("app.services.action_scheduler.publish_event", mock_publish_event)

    mocker.patch("app.actions.handlers.get_auth_config", return_value=auth_config)
    mock_get_trips = mocker.patch(
        "app.datasource.ctrackcrystal.get_trips",
        new_callable=AsyncMock,
        return_value=trips_response
    )
    mocker.patch("app.actions.handlers.state_manager.get_state", new_callable=AsyncMock, return_value=None)
    mock_get_trip_summary = mocker.patch(
        "app.datasource.ctrackcrystal.get_detailed_trip_summary",
        new_callable=AsyncMock,
        return_value=ctrackcrystal.DetailedTripSummaryResponse(location_summary=[ctrackcrystal.LocationSummary(latitude=1.0, longitude=2.0, event_time=datetime.now(timezone.utc))])
    )
    mock_send_observations = mocker.patch("app.actions.handlers.send_observations_to_gundi", new_callable=AsyncMock, return_value=[1])
    mock_set_state = mocker.patch("app.actions.handlers.state_manager.set_state", new_callable=AsyncMock)

    result = await handlers.action_fetch_vehicle_trips(integration, action_config)

    assert result["observations_extracted"] == 1
    mock_get_trips.assert_awaited_once()
    mock_get_trip_summary.assert_awaited()
    mock_send_observations.assert_awaited()
    mock_set_state.assert_awaited()
    # State must include processed_trips when saving
    call_kwargs = mock_set_state.call_args[1]
    assert "state" in call_kwargs
    assert "processed_trips" in call_kwargs["state"]
    assert "updated_at" in call_kwargs["state"]


@pytest.mark.asyncio
async def test_fetch_one_vehicle_trips_observations_skips_trip_in_processed_trips(mocker):
    """When a trip is already in processed_trips with stored trip_end_time >= current, DetailedTripSummary is not called."""
    base_url = "https://api.example.com"
    auth_config = MagicMock()
    auth_config.subscription_key = pydantic.SecretStr("key")
    trip_end = datetime.now(timezone.utc) - timedelta(hours=1)
    action_config = PullVehicleTripsConfig(
        vehicle_id="veh1",
        vehicle_serial_number="sn1",
        vehicle_display_name="V1",
        filter_day=datetime.now(timezone.utc),
    )
    token = MagicMock(jwt="jwt")

    trip_detail = ctrackcrystal.TripDetail(
        date=trip_end,
        tripId="trip_123",
        tripendTime=trip_end,
    )
    trip = ctrackcrystal.Trip(id="t1", details=[trip_detail])
    trips_response = ctrackcrystal.TripsResponse(count=1, payload=[trip])

    mock_get_trips = mocker.patch(
        "app.datasource.ctrackcrystal.get_trips",
        new_callable=AsyncMock,
        return_value=trips_response,
    )
    mock_get_summary = mocker.patch(
        "app.datasource.ctrackcrystal.get_detailed_trip_summary",
        new_callable=AsyncMock,
    )

    processed_trips = {"trip_123": trip_end}
    out = []
    async for obs in handlers._fetch_one_vehicle_trips_observations(
        token, auth_config, base_url, action_config,
        integration_id="",
        processed_trips=processed_trips,
    ):
        out.append(obs)

    assert len(out) == 0
    mock_get_trips.assert_awaited_once()
    mock_get_summary.assert_not_awaited()


@pytest.mark.asyncio
async def test_action_fetch_vehicle_trips_exception(mocker, mock_publish_event):
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
    mock_token = MagicMock(jwt="token", valid_to_utc=datetime.now(timezone.utc) + timedelta(hours=1))
    mocker.patch("app.actions.handlers.retrieve_token", new_callable=AsyncMock, return_value=mock_token)
    mocker.patch("app.datasource.ctrackcrystal.get_trips", new_callable=AsyncMock, side_effect=Exception("fail"))
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
        "app.datasource.ctrackcrystal.get_trips",
        new_callable=AsyncMock,
        side_effect=ctrackcrystal.TooManyRequestsException("Rate Limit reached", None),
    )
    mock_token = MagicMock(jwt="token", valid_to_utc=datetime.now(timezone.utc) + timedelta(hours=1))
    mocker.patch("app.actions.handlers.retrieve_token", new_callable=AsyncMock, return_value=mock_token)

    mock_log_action_activity = mocker.patch("app.actions.handlers.log_action_activity", new_callable=AsyncMock)

    result = await handlers.action_fetch_vehicle_trips(integration, action_config)

    assert result["observations_extracted"] == 0
    mock_log_action_activity.assert_awaited_once()
    kwargs = mock_log_action_activity.call_args[1]
    assert "rate limit" in kwargs.get("title", "").lower()
