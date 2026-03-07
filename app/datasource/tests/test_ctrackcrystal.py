"""Unit tests for app.datasource.ctrackcrystal (models and client retry behavior)."""

from datetime import date, datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.datasource.ctrackcrystal import (
    DetailedTripSummaryResponse,
    GetVehiclesResponse,
    InternalServerException,
    LocationSummary,
    LoginResponse,
    ReadTimeoutException,
    TooManyRequestsException,
    Trip,
    TripDetail,
    TripsResponse,
    Vehicle,
    get_detailed_trip_summary,
    get_trips,
    get_vehicles,
    login,
    refresh_token,
)
from app.datasource.ctrackcrystal.client import (
    _get_retry_after,
    _handle_httpx_error,
    _wait_seconds_for_exception,
)
# --- Model parsing ---


def test_login_response_parsing():
    data = {
        "jwt": "eyJ0eXAiOiJKV1QiLCJhbGc...",
        "validToUtc": "2023-03-27T14:30:00Z",
    }
    obj = LoginResponse.parse_obj(data)
    assert obj.jwt == data["jwt"]
    assert obj.valid_to_utc.tzinfo is not None


def test_vehicle_parsing_last_reported_time():
    data = {
        "id": "VEHICLE-NA-abc",
        "serialNumber": "sn123",
        "displayName": "Truck 1",
        "lastReportedTime": "2023-03-27T12:00:00Z",
    }
    obj = Vehicle.parse_obj(data)
    assert obj.id == data["id"]
    assert obj.last_reported_time is not None
    assert obj.last_reported_time.tzinfo is not None


def test_get_vehicles_response_parsing():
    data = {
        "count": 1,
        "vehicles": [
            {
                "id": "v1",
                "serialNumber": "s1",
                "displayName": "V1",
                "lastReportedTime": "2023-03-27T10:00:00Z",
            }
        ],
    }
    obj = GetVehiclesResponse.parse_obj(data)
    assert obj.count == 1
    assert len(obj.vehicles) == 1
    assert obj.vehicles[0].display_name == "V1"


def test_trip_detail_parsing_trip_end_time():
    """TripDetail uses tripendTime alias (API returns tripendTime)."""
    data = {
        "date": "2023-03-27T00:00:00Z",
        "tripId": "CTOS-NX12-0356601060033946-1679909933000",
        "tripStartTime": "2023-03-27T08:00:00Z",
        "tripendTime": "2023-03-27T09:30:00Z",
    }
    obj = TripDetail.parse_obj(data)
    assert obj.trip_id == data["tripId"]
    assert obj.trip_start_time is not None
    assert obj.trip_end_time is not None


def test_trips_response_parsing():
    data = {
        "count": 1,
        "payload": [
            {
                "id": "v1",
                "details": [
                    {
                        "date": "2023-03-27T00:00:00Z",
                        "tripId": "t1",
                        "tripStartTime": "2023-03-27T08:00:00Z",
                        "tripendTime": "2023-03-27T09:00:00Z",
                    }
                ],
            }
        ],
    }
    obj = TripsResponse.parse_obj(data)
    assert obj.count == 1
    assert len(obj.payload) == 1
    assert len(obj.payload[0].details) == 1
    assert obj.payload[0].details[0].trip_id == "t1"


def test_location_summary_parsing():
    data = {
        "eventTime": "2023-03-27T08:15:00Z",
        "latitude": -33.9,
        "longitude": 18.4,
    }
    obj = LocationSummary.parse_obj(data)
    assert obj.event_time is not None
    assert obj.latitude == -33.9
    assert obj.longitude == 18.4


def test_detailed_trip_summary_response_coerces_null_location_summary():
    """locationSummary null should become []."""
    data = {"locationSummary": None}
    obj = DetailedTripSummaryResponse.parse_obj(data)
    assert obj.location_summary == []


def test_detailed_trip_summary_response_parsing():
    data = {
        "locationSummary": [
            {"eventTime": "2023-03-27T08:00:00Z", "latitude": 1.0, "longitude": 2.0}
        ]
    }
    obj = DetailedTripSummaryResponse.parse_obj(data)
    assert len(obj.location_summary) == 1
    assert obj.location_summary[0].latitude == 1.0


# --- Retry / exception helpers ---


def test_get_retry_after_uses_header():
    """_get_retry_after should return Retry-After header value in seconds."""
    response = MagicMock()
    response.headers = {"Retry-After": "23"}
    http_err = httpx.HTTPStatusError("429", request=MagicMock(), response=response)
    exc = TooManyRequestsException("Rate limit", http_err)
    wait = _get_retry_after(exc)
    assert wait == 23


def test_wait_seconds_for_internal_server_uses_fixed_delay():
    from app.datasource.ctrackcrystal.exceptions import InternalServerException as ISE
    exc = ISE("Server error", None, status_code=500)
    wait = _wait_seconds_for_exception(exc)
    assert wait == 15


def test_wait_seconds_for_read_timeout_uses_fixed_delay():
    exc = ReadTimeoutException("Read timeout", None)
    wait = _wait_seconds_for_exception(exc)
    assert wait == 15


def test_handle_httpx_error_429():
    err = httpx.HTTPStatusError(
        "429",
        request=MagicMock(),
        response=MagicMock(status_code=429, headers={}),
    )
    with pytest.raises(TooManyRequestsException):
        _handle_httpx_error(err)


def test_handle_httpx_error_500():
    from app.datasource.ctrackcrystal.exceptions import InternalServerException as ISE
    err = httpx.HTTPStatusError(
        "500",
        request=MagicMock(),
        response=MagicMock(status_code=500, headers={}),
    )
    with pytest.raises(ISE) as exc_info:
        _handle_httpx_error(err)
    assert exc_info.value.status_code == 500


# --- Client: login ---


@pytest.mark.asyncio
async def test_login_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "jwt": "token123",
        "validToUtc": datetime.now(timezone.utc).isoformat(),
    }
    mock_response.raise_for_status = MagicMock()

    session = AsyncMock()
    session.post = AsyncMock(return_value=mock_response)
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    result = await login(
        "https://api.example.com",
        "user",
        "pass",
        "sub-key",
    )
    assert result is not None
    assert result.jwt == "token123"


@pytest.mark.asyncio
async def test_login_429_raises_and_retries(mocker):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    response = MagicMock()
    response.is_error = True
    response.status_code = 429
    response.headers = {"Retry-After": "2"}
    response.text = "rate limit"
    err = httpx.HTTPStatusError("429", request=MagicMock(), response=response)
    response.raise_for_status.side_effect = err

    session = AsyncMock()
    session.post = AsyncMock(return_value=response)
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(TooManyRequestsException):
        await login("https://api.example.com", "u", "p", "key")


@pytest.mark.asyncio
async def test_login_500_retries_then_raises(mocker):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    response = MagicMock()
    response.is_error = True
    response.status_code = 500
    response.headers = {}
    response.text = "error"
    err = httpx.HTTPStatusError("500", request=MagicMock(), response=response)
    response.raise_for_status.side_effect = err

    session = AsyncMock()
    session.post = AsyncMock(return_value=response)
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(InternalServerException):
        await login("https://api.example.com", "u", "p", "key")


@pytest.mark.asyncio
async def test_login_read_timeout_retries_then_raises(mocker):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    session = AsyncMock()
    session.post = AsyncMock(side_effect=httpx.ReadTimeout("read timeout"))
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(ReadTimeoutException):
        await login("https://api.example.com", "u", "p", "key")


# --- Client: get_vehicles ---


@pytest.mark.asyncio
async def test_get_vehicles_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "count": 1,
        "vehicles": [
            {"id": "v1", "serialNumber": "s1", "displayName": "V1", "lastReportedTime": "2023-03-27T12:00:00Z"}
        ],
    }
    mock_response.raise_for_status = MagicMock()

    session = AsyncMock()
    session.get = AsyncMock(return_value=mock_response)
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    result = await get_vehicles("https://api.example.com", "token", "sub-key")
    assert result.count == 1
    assert len(result.vehicles) == 1
    assert result.vehicles[0].id == "v1"


# --- Client: get_trips (batch) ---


@pytest.mark.asyncio
async def test_get_trips_success_batch(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "count": 1,
        "payload": [
            {
                "id": "v1",
                "details": [
                    {
                        "date": "2023-03-27T00:00:00Z",
                        "tripId": "t1",
                        "tripStartTime": "2023-03-27T08:00:00Z",
                        "tripendTime": "2023-03-27T09:00:00Z",
                    }
                ],
            }
        ],
    }
    mock_response.raise_for_status = MagicMock()

    session = AsyncMock()
    session.post = AsyncMock(return_value=mock_response)
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    result = await get_trips(
        "https://api.example.com",
        "token",
        "sub-key",
        ["v1", "v2"],
        date(2023, 3, 27),
    )
    assert result.count == 1
    assert len(result.payload) == 1
    session.post.assert_called_once()
    call_kw = session.post.call_args[1]
    assert call_kw["json"]["ids"] == ["v1", "v2"]
    assert call_kw["params"]["filterDay"] == "2023-03-27"


@pytest.mark.asyncio
async def test_get_trips_empty_vehicle_ids_returns_empty(mocker):
    result = await get_trips(
        "https://api.example.com",
        "token",
        "sub-key",
        [],
        date(2023, 3, 27),
    )
    assert result.count == 0
    assert result.payload == []


# --- Client: get_detailed_trip_summary ---


@pytest.mark.asyncio
async def test_get_detailed_trip_summary_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "locationSummary": [
            {"eventTime": "2023-03-27T08:00:00Z", "latitude": 1.0, "longitude": 2.0}
        ]
    }
    mock_response.raise_for_status = MagicMock()

    session = AsyncMock()
    session.get = AsyncMock(return_value=mock_response)
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    result = await get_detailed_trip_summary(
        "https://api.example.com",
        "token",
        "sub-key",
        "trip-id-123",
    )
    assert len(result.location_summary) == 1
    assert result.location_summary[0].latitude == 1.0
