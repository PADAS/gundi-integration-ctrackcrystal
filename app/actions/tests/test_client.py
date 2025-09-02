import pytest
import httpx
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
from app.actions.client import (
    get_token,
    refresh_token,
    get_vehicles,
    get_vehicle_trips,
    get_trip_summary,
    CTCUnauthorizedException,
    CTCForbiddenException,
    CTCTooManyRequestsException,
    CTCInternalServerException,
)


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


@pytest.mark.asyncio
async def test_get_token_success(mocker):
    # Mock response object
    mock_response = MagicMock()
    mock_response.is_error = False
    mock_response.json.return_value = {
        "jwt": "token123",
        "validToUtc": datetime.now(timezone.utc).isoformat()
    }
    mock_response.raise_for_status = MagicMock()

    # Mock AsyncClient as async context manager
    mock_post = AsyncMock(return_value=mock_response)
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.post = mock_post
    mock_client.__aexit__.return_value = AsyncMock()

    mocker.patch("httpx.AsyncClient", return_value=mock_client)

    token = await get_token(
        "integration_id",
        "http://base.url",
        "user",
        MagicMock(get_secret_value=lambda: "pass"),
        MagicMock(get_secret_value=lambda: "subkey")
    )
    assert token.jwt == "token123"

@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, CTCUnauthorizedException),
    (403, CTCForbiddenException),
    (429, CTCTooManyRequestsException),
    (500, CTCInternalServerException),
])
async def test_get_token_http_errors(mocker, status_code, exception_type):
    # Build a fake response whose raise_for_status raises the HTTPStatusError
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

    # session.post returns the response (no exception yet)
    session = AsyncMock()
    session.post = AsyncMock(return_value=response)

    # Proper async context manager for httpx.AsyncClient
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(exception_type):
        await get_token(
            "integration_id",
            "http://base.url",
            "user",
            MagicMock(get_secret_value=lambda: "pass"),
            MagicMock(get_secret_value=lambda: "subkey")
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
        "integration_id",
        "http://base.url",
        "token",
        MagicMock(get_secret_value=lambda: "subkey")
    )
    assert token.jwt == "token456"

@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, CTCUnauthorizedException),
    (403, CTCForbiddenException),
    (429, CTCTooManyRequestsException),
    (500, CTCInternalServerException),
])
async def test_refresh_token_http_errors(mocker, status_code, exception_type):
    # Response whose raise_for_status raises the httpx.HTTPStatusError
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

    # session.post returns the response
    session = AsyncMock()
    session.post = AsyncMock(return_value=response)

    # Proper async context manager
    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    with pytest.raises(exception_type):
        await refresh_token(
            "integration_id",
            "http://base.url",
            "token123",
            MagicMock(get_secret_value=lambda: "subkey")
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
    mocker.patch("app.actions.client.retrieve_token", return_value=AsyncMock(jwt="token123"))

    integration = MagicMock()
    integration.id = "integration_id"
    subscription_key = MagicMock(get_secret_value=lambda: "subkey")

    vehicles_response = await get_vehicles(integration, subscription_key, "http://base.url")
    assert vehicles_response.count == 1
    assert vehicles_response.vehicles[0].id == "veh1"

@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, CTCUnauthorizedException),
    (403, CTCForbiddenException),
    (500, CTCInternalServerException),
])
async def test_get_vehicles_http_errors(mocker, status_code, exception_type):
    response = _mk_http_error_response(status_code)

    session = AsyncMock()
    session.get = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    mocker.patch("app.actions.client.retrieve_token",
                 AsyncMock(return_value=SimpleNamespace(jwt="token123")))

    integration = SimpleNamespace(id="integration_id")
    subscription_key = MagicMock(get_secret_value=lambda: "subkey")

    with pytest.raises(exception_type):
        await get_vehicles(integration, subscription_key, "http://base.url")

@pytest.mark.asyncio
async def test_get_vehicle_trips_success(mocker):
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
    mocker.patch("app.actions.client.retrieve_token", return_value=AsyncMock(jwt="token123"))

    integration = MagicMock()
    integration.id = "integration_id"
    subscription_key = MagicMock(get_secret_value=lambda: "subkey")

    trips_response = await get_vehicle_trips(
        integration,
        subscription_key,
        "http://base.url",
        "veh1",
        datetime.now(timezone.utc)
    )
    assert trips_response.count == 1
    assert trips_response.payload[0].id == "trip1"

@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, CTCUnauthorizedException),
    (403, CTCForbiddenException),
    (500, CTCInternalServerException),
])
async def test_get_vehicle_trips_http_errors(mocker, status_code, exception_type):
    # Use the same pattern as other *_http_errors tests: post returns a response
    # whose raise_for_status triggers the httpx.HTTPStatusError.
    response = _mk_http_error_response(status_code)

    session = AsyncMock()
    session.post = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    mocker.patch("app.actions.client.retrieve_token", return_value=AsyncMock(jwt="token123"))

    integration = MagicMock()
    integration.id = "integration_id"
    subscription_key = MagicMock(get_secret_value=lambda: "subkey")

    with pytest.raises(exception_type):
        await get_vehicle_trips(
            integration,
            subscription_key,
            "http://base.url",
            "veh1",
            datetime.now(timezone.utc)
        )

@pytest.mark.asyncio
async def test_get_trip_summary_success(mocker):
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
    mocker.patch("app.actions.client.retrieve_token", return_value=AsyncMock(jwt="token123"))

    integration = MagicMock()
    integration.id = "integration_id"
    subscription_key = MagicMock(get_secret_value=lambda: "subkey")

    trip_summary = await get_trip_summary(
        integration,
        subscription_key,
        "http://base.url",
        "veh1",
        "trip1"
    )
    assert len(trip_summary.locationSummary) == 1

@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,exception_type", [
    (401, CTCUnauthorizedException),
    (403, CTCForbiddenException),
    (500, CTCInternalServerException),
])
async def test_get_trip_summary_http_errors(mocker, status_code, exception_type):
    response = _mk_http_error_response(status_code)

    session = AsyncMock()
    session.get = AsyncMock(return_value=response)

    client_cm = AsyncMock()
    client_cm.__aenter__.return_value = session
    client_cm.__aexit__.return_value = False
    mocker.patch("httpx.AsyncClient", return_value=client_cm)

    mocker.patch("app.actions.client.retrieve_token",
                 AsyncMock(return_value=SimpleNamespace(jwt="token123")))

    integration = SimpleNamespace(id="integration_id")
    subscription_key = MagicMock(get_secret_value=lambda: "subkey")

    with pytest.raises(exception_type):
        await get_trip_summary(
            integration,
            subscription_key,
            "http://base.url",
            "veh1",
            "trip1"
        )
