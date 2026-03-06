import pytest
import httpx
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone, date
from app.datasource.ctrackcrystal import (
    login,
    refresh_token,
    get_vehicles,
    get_trips,
    get_detailed_trip_summary,
    UnauthorizedException,
    ForbiddenException,
    TooManyRequestsException,
    InternalServerException,
)
from app.datasource.ctrackcrystal.client import _get_retry_after


def _mk_http_error_response(status_code: int):
    resp = MagicMock()
    resp.is_error = True
    resp.status_code = status_code
    resp.headers = {}
    http_err = httpx.HTTPStatusError(
        message="error",
        request=MagicMock(),
        response=MagicMock(status_code=status_code, headers={})
    )
    resp.raise_for_status.side_effect = http_err
    return resp


def _mk_429_exception(retry_after_header=None):
    """Build TooManyRequestsException with optional Retry-After header."""
    headers = {} if retry_after_header is None else {"Retry-After": retry_after_header}
    response = MagicMock()
    response.status_code = 429
    response.headers = headers
    http_err = httpx.HTTPStatusError("rate limit", request=MagicMock(), response=response)
    return TooManyRequestsException("Rate Limit reached", http_err)


@pytest.mark.asyncio
async def test_login_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "jwt": "token123",
        "validToUtc": datetime.now(timezone.utc).isoformat()
    }
    mock_response.raise_for_status = MagicMock()

    mock_post = AsyncMock(return_value=mock_response)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.post = mock_post
    mock_client.__aexit__.return_value = AsyncMock()

    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    token = await login(
        "http://base.url",
        "user",
        "some-fancy-password",
        "fancy-subscription-key"
    )
    assert token is not None
    assert token.jwt == "token123"


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, UnauthorizedException),
    (403, ForbiddenException),
    (429, TooManyRequestsException),
    (500, InternalServerException),
])
async def test_login_http_errors(mocker, status_code, exception_type):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    response = MagicMock()
    response.is_error = True
    response.status_code = status_code
    response.headers = {}
    http_err = httpx.HTTPStatusError(
        message="error",
        request=MagicMock(),
        response=MagicMock(status_code=status_code, headers={})
    )
    response.raise_for_status.side_effect = http_err

    session = AsyncMock()
    session.post = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(exception_type):
        await login(
            "http://base.url",
            "user",
            "some-fancy-password",
            "fancy-subscription-key"
        )


@pytest.mark.asyncio
async def test_refresh_token_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "jwt": "token456",
        "validToUtc": datetime.now(timezone.utc).isoformat()
    }
    mock_response.raise_for_status = MagicMock()

    mock_post = AsyncMock(return_value=mock_response)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.post = mock_post
    mock_client.__aexit__.return_value = AsyncMock()

    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    token = await refresh_token(
        "http://base.url",
        "token",
        "fancy-subscription-key"
    )
    assert token is not None
    assert token.jwt == "token456"


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, UnauthorizedException),
    (403, ForbiddenException),
    (429, TooManyRequestsException),
    (500, InternalServerException),
])
async def test_refresh_token_http_errors(mocker, status_code, exception_type):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    response = MagicMock()
    response.is_error = True
    response.status_code = status_code
    response.headers = {}
    http_err = httpx.HTTPStatusError(
        message="error",
        request=MagicMock(),
        response=MagicMock(status_code=status_code, headers={})
    )
    response.raise_for_status.side_effect = http_err

    session = AsyncMock()
    session.post = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(exception_type):
        await refresh_token(
            "http://base.url",
            "token123",
            "fancy-subscription-key"
        )


@pytest.mark.asyncio
async def test_get_vehicles_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "count": 1,
        "vehicles": [
            {
                "id": "veh1",
                "serialNumber": "sn1",
                "displayName": "Vehicle 1"
            }
        ]
    }
    mock_response.raise_for_status = MagicMock()

    mock_get = AsyncMock(return_value=mock_response)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.get = mock_get
    mock_client.__aexit__.return_value = AsyncMock()

    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    vehicles_response = await get_vehicles(
        "http://base.url",
        "token123",
        "fancy-subscription-key"
    )
    assert vehicles_response.count == 1
    assert vehicles_response.vehicles[0].id == "veh1"


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, UnauthorizedException),
    (403, ForbiddenException),
    (500, InternalServerException),
])
async def test_get_vehicles_http_errors(mocker, status_code, exception_type):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    response = _mk_http_error_response(status_code)

    session = AsyncMock()
    session.get = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(exception_type):
        await get_vehicles(
            "http://base.url",
            "token123",
            "fancy-subscription-key"
        )


@pytest.mark.asyncio
async def test_get_trips_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "count": 1,
        "payload": [
            {
                "id": "trip1",
                "tripCount": 1,
                "details": []
            }
        ]
    }
    mock_response.raise_for_status = MagicMock()

    mock_post = AsyncMock(return_value=mock_response)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.post = mock_post
    mock_client.__aexit__.return_value = AsyncMock()

    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    trips_response = await get_trips(
        "http://base.url",
        "token123",
        "fancy-subscription-key",
        ["veh1"],
        date.today()
    )
    assert trips_response.count == 1
    assert trips_response.payload[0].id == "trip1"


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, UnauthorizedException),
    (403, ForbiddenException),
    (500, InternalServerException),
])
async def test_get_trips_http_errors(mocker, status_code, exception_type):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    response = _mk_http_error_response(status_code)

    session = AsyncMock()
    session.post = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(exception_type):
        await get_trips(
            "http://base.url",
            "token123",
            "fancy-subscription-key",
            ["veh1"],
            date.today()
        )


@pytest.mark.asyncio
async def test_get_detailed_trip_summary_success(mocker):
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "locationSummary": [
            {
                "eventId": 1,
                "eventTime": datetime.now(timezone.utc).isoformat(),
                "latitude": 10.0,
                "longitude": 20.0
            }
        ]
    }
    mock_response.raise_for_status = MagicMock()

    mock_get = AsyncMock(return_value=mock_response)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.get = mock_get
    mock_client.__aexit__.return_value = AsyncMock()

    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    trip_summary = await get_detailed_trip_summary(
        "http://base.url",
        "token123",
        "fancy-subscription-key",
        "trip1"
    )
    assert len(trip_summary.location_summary) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, UnauthorizedException),
    (403, ForbiddenException),
    (500, InternalServerException),
])
async def test_get_detailed_trip_summary_http_errors(mocker, status_code, exception_type):
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    response = _mk_http_error_response(status_code)

    session = AsyncMock()
    session.get = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(exception_type):
        await get_detailed_trip_summary(
            "http://base.url",
            "token123",
            "fancy-subscription-key",
            "trip1"
        )


def test_get_retry_after_missing_header_returns_at_least_one():
    exc = _mk_429_exception(retry_after_header=None)
    assert _get_retry_after(exc) >= 1
    assert _get_retry_after(exc) == 10


def test_get_retry_after_zero_enforces_minimum_one():
    exc = _mk_429_exception(retry_after_header="0")
    assert _get_retry_after(exc) == 1


def test_get_retry_after_delay_seconds():
    exc = _mk_429_exception(retry_after_header="5")
    assert _get_retry_after(exc) == 5
