import backoff
import httpx
import pydantic
import logging

from datetime import datetime, timezone, timedelta
from typing import List, Optional

from gundi_core.schemas.v2 import Integration

from app.actions.configurations import get_auth_config
from app.services.state import IntegrationStateManager


logger = logging.getLogger(__name__)
state_manager = IntegrationStateManager()


class UTCNormalizedModel(pydantic.BaseModel):
    @pydantic.root_validator
    def _ensure_datetime_tz(cls, values):
        for k, v in values.items():
            if isinstance(v, datetime) and v.tzinfo is None:
                values[k] = v.replace(tzinfo=timezone.utc)
        return values


class CTCLoginResponse(UTCNormalizedModel):
    jwt: str
    valid_to_utc: datetime = Field(..., alias="validToUtc")
    
    class Config:
        allow_population_by_field_name = True

class CTCDevicesList(pydantic.BaseModel):
    id: Optional[str]
    unitType: Optional[str]
    hardwareType: Optional[str]


class CTCVehicle(UTCNormalizedModel):
    id: str
    serialNumber: str
    displayName: str
    fleetNumber: Optional[str]
    registrationNumber: Optional[str]
    vin: Optional[str]
    make: Optional[str]
    model: Optional[str]
    color: Optional[str]
    driverId: Optional[str]
    odometer: Optional[int]
    runningHours: Optional[int]
    firstStartUpTime: Optional[datetime]
    lastReportedTime: Optional[datetime]
    devicesList: Optional[List[CTCDevicesList]]


class CTCTripDetail(UTCNormalizedModel):
    date: datetime
    tripId: str
    tripStartTime: Optional[datetime]
    tripendTime: Optional[datetime]
    distanceDriven: Optional[float]
    currentDistance: Optional[float]
    runningDistance: Optional[float]
    runningDuration: Optional[float]
    driveTime: Optional[float]
    idleTime: Optional[float]
    maxSpeed: Optional[float]
    stopTime: Optional[float]
    tripMode: Optional[str]
    tripStartLatitude: Optional[str]
    tripStartLongitude: Optional[str]
    tripEndLatitude: Optional[str]
    tripEndLongitude: Optional[str]
    startLocationDetail: Optional[str]
    endLocationDetail: Optional[str]


class CTCTrip(pydantic.BaseModel):
    id: str
    tripCount: Optional[int]
    totalDistance: Optional[float]
    totalStopTime: Optional[float]
    totalIdleTime: Optional[float]
    totalDriveTime: Optional[float]
    totalViolationCount: Optional[float]
    maxSpeed: Optional[float]
    averageDailyDistance: Optional[float]
    averageVehicleDistance: Optional[float]
    details: List[CTCTripDetail]


class CTCLocationSummary(UTCNormalizedModel):
    eventId: Optional[int]
    eventTime: datetime
    eventText: Optional[str]
    latitude: float
    longitude: float
    speed: Optional[float]
    distance: Optional[float]
    heading: Optional[int]
    direction: Optional[str]
    runningDistance: Optional[float]


class CTCDetailedTripSummaryResponse(pydantic.BaseModel):
    locationSummary: List[CTCLocationSummary]


class CTCTripsResponse(pydantic.BaseModel):
    count: int
    payload: List[CTCTrip]


class CTCGetVehiclesResponse(pydantic.BaseModel):
    count: int
    vehicles: List[CTCVehicle]


class CTCTooManyRequestsException(Exception):
    def __init__(self, message: str, error: Exception = None, status_code=429):
        self.status_code = status_code
        self.message = message
        self.error = error
        super().__init__(f"'{self.status_code}: {self.message}, Error: {self.error}'")


class CTCNotFoundException(Exception):
    def __init__(self, message: str, error: Exception = None, status_code=404):
        self.status_code = status_code
        self.message = message
        self.error = error
        super().__init__(f"'{self.status_code}: {self.message}, Error: {self.error}'")


class CTCUnauthorizedException(Exception):
    def __init__(self, message: str, error: Exception = None, status_code=401):
        self.status_code = status_code
        self.message = message
        self.error = error
        super().__init__(f"'{self.status_code}: {self.message}, Error: {self.error}'")


class CTCForbiddenException(Exception):
    def __init__(self, message: str, error: Exception = None, status_code=403):
        self.status_code = status_code
        self.message = message
        self.error = error
        super().__init__(f"'{self.status_code}: {self.message}, Error: {self.error}'")


class CTCInternalServerException(Exception):
    def __init__(self, message: str, error: Exception = None, status_code=500):
        self.status_code = status_code
        self.message = message
        self.error = error
        super().__init__(f"'{self.status_code}: {self.message}, Error: {self.error}'")


def _get_retry_after(exc):
    """Extract Retry-After header value in seconds from exception."""
    retry_after = 0
    try:
        retry_after_header = exc.response.headers.get("Retry-After")
        if retry_after_header:
            retry_after = int(retry_after_header)
    except Exception:
        retry_after = 1
    return retry_after

async def retrieve_token(integration: Integration, base_url: str) -> CTCLoginResponse:
    """
        Helper function to retrieve token from state or CTC API.
    """
    integration_id = str(integration.id)

    saved_token = await state_manager.get_state(
        integration_id,
        "auth",
        "token"
    )

    auth_config = None
    if not saved_token:
        auth_config = get_auth_config(integration)
        token = await get_token(
            integration_id,
            base_url,
            auth_config.username,
            auth_config.password,
            auth_config.subscription_key
        )
    else:
        token = CTCLoginResponse.parse_obj(saved_token)

    # Check if token is expired or about to expire in the next 5 minutes
    if datetime.now(timezone.utc) >= token.validToUtc - timedelta(minutes=5):
        if auth_config is None:
            auth_config = get_auth_config(integration)
        token = await refresh_token(
            integration_id,
            base_url,
            token.jwt,
            auth_config.subscription_key
        )

    await state_manager.set_state(
        integration_id,
        "auth",
        {"jwt": token.jwt, "validToUtc": token.validToUtc.isoformat()},
        "token"
    )

    return token

async def get_token(
        integration_id: str,
        base_url: str,
        username: str,
        password: pydantic.SecretStr,
        subscription_key: pydantic.SecretStr
) -> CTCLoginResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        logger.info(f"-- Getting token for integration ID: {integration_id} Username: {username} --")

        url = f"{base_url}/Authenticate/Login"

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value()
        }

        params = {
            "username": username,
            "password": password.get_secret_value()
        }

        try:
            response = await session.post(url, json=params, headers=headers)
            if response.is_error:
                logger.error(f"Error in 'get_token' endpoint. Response body: {response.text}")
            response.raise_for_status()
            parsed_response = response.json()
            if parsed_response:
                return CTCLoginResponse.parse_obj(parsed_response)
            else:
                logger.warning( f"-- Login failed for integration ID: {integration_id} Username: {username} --")
                return None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise CTCUnauthorizedException("Unauthorized access", e)
            if e.response.status_code == 403:
                raise CTCForbiddenException("Forbidden access", e)
            if e.response.status_code == 429:
                raise CTCTooManyRequestsException("Rate Limit reached", e)
            elif e.response.status_code == 500:
                raise CTCInternalServerException("Internal server error", e)
            raise e

async def refresh_token(
        integration_id: str,
        base_url: str,
        token: str,
        subscription_key: pydantic.SecretStr
) -> CTCLoginResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        logger.info(f"-- Refreshing token for integration ID: {integration_id} --")

        url = f"{base_url}/Authenticate/RefreshToken"

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value(),
            "x-token": token
        }

        try:
            response = await session.post(url, headers=headers)
            if response.is_error:
                logger.error(f"Error in 'refresh_token' endpoint. Response body: {response.text}")
            response.raise_for_status()
            parsed_response = response.json()
            if parsed_response:
                return CTCLoginResponse.parse_obj(parsed_response)
            else:
                logger.warning(f"-- Token refresh failed for integration ID: {integration_id} --")
                return None
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise CTCUnauthorizedException("Unauthorized access", e)
            if e.response.status_code == 403:
                raise CTCForbiddenException("Forbidden access", e)
            if e.response.status_code == 429:
                raise CTCTooManyRequestsException("Rate Limit reached", e)
            elif e.response.status_code == 500:
                raise CTCInternalServerException("Internal server error", e)
            raise e

@backoff.on_exception(
        backoff.constant,
        CTCTooManyRequestsException,
        max_tries=3,
        jitter=None,
        interval=lambda e: _get_retry_after(e)
)
async def get_vehicles(
        integration: Integration,
        subscription_key: pydantic.SecretStr,
        base_url: str
) -> CTCGetVehiclesResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        logger.info(f"-- Getting vehicles for integration ID: {integration.id} --")

        url = f"{base_url}/Vehicle/GetVehicles"

        token = await retrieve_token(integration, base_url)

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value(),
            "x-token": token.jwt
        }

        try:
            response = await session.get(url, headers=headers)
            if response.is_error:
                logger.error(f"Error 'get_vehicles' endpoint. Response body: {response.text}")
            response.raise_for_status()
            parsed_response = response.json()
            if parsed_response:
                return CTCGetVehiclesResponse.parse_obj(parsed_response)
            else:
                logger.warning(f"-- No vehicles returned for integration ID: {integration.id}: {response.text}  --")
                return CTCGetVehiclesResponse()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise CTCUnauthorizedException("Unauthorized access", e)
            if e.response.status_code == 403:
                raise CTCForbiddenException("Forbidden access", e)
            if e.response.status_code == 429:
                raise CTCTooManyRequestsException("Rate Limit reached", e)
            elif e.response.status_code == 500:
                raise CTCInternalServerException("Internal server error", e)
            raise e

@backoff.on_exception(
        backoff.constant,
        CTCTooManyRequestsException,
        max_tries=3,
        jitter=None,
        interval=lambda e: _get_retry_after(e)
)
async def get_vehicle_trips(
        integration: Integration,
        subscription_key: pydantic.SecretStr,
        base_url: str,
        vehicle_id: str,
        filter_day: datetime
) -> CTCTripsResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        logger.info(f"-- Getting vehicle trips for integration ID: {integration.id} Vehicle ID: {vehicle_id} --")

        url = f"{base_url}/Vehicle/Trips"

        token = await retrieve_token(integration, base_url)

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value(),
            "x-token": token.jwt
        }

        try:
            response = await session.post(
                url,
                headers=headers,
                params={"filterDay": filter_day.strftime("%Y-%m-%d")},
                json={"ids": [vehicle_id]}
            )
            if response.is_error:
                logger.error(f"Error 'get_vehicle_trips' endpoint. Response body: {response.text}")
            response.raise_for_status()
            parsed_response = response.json()
            if parsed_response:
                return CTCTripsResponse.parse_obj(parsed_response)
            else:
                logger.warning(f"-- No trips returned for integration ID: {integration.id}: Vehicle ID {vehicle_id}: {response.text}  --")
                return CTCTripsResponse()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise CTCUnauthorizedException("Unauthorized access", e)
            if e.response.status_code == 403:
                raise CTCForbiddenException("Forbidden access", e)
            if e.response.status_code == 429:
                raise CTCTooManyRequestsException("Rate Limit reached", e)
            elif e.response.status_code == 500:
                raise CTCInternalServerException("Internal server error", e)
            raise e

@backoff.on_exception(
        backoff.constant,
        CTCTooManyRequestsException,
        max_tries=3,
        jitter=None,
        interval=lambda e: _get_retry_after(e)
)
async def get_trip_summary(
        integration: Integration,
        subscription_key: pydantic.SecretStr,
        base_url: str,
        vehicle_id: str,
        trip_id: str
) -> CTCDetailedTripSummaryResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        logger.info(f"-- Getting trip {trip_id} summary for integration ID: {integration.id} Vehicle ID: {vehicle_id} --")

        url = f"{base_url}/Vehicle/DetailedTripSummary/{trip_id}"

        token = await retrieve_token(integration, base_url)

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value(),
            "x-token": token.jwt
        }

        try:
            response = await session.get(
                url,
                headers=headers
            )
            if response.is_error:
                logger.error(f"Error 'get_trip_summary' endpoint. Response body: {response.text}")
            response.raise_for_status()
            parsed_response = response.json()
            if parsed_response:
                return CTCDetailedTripSummaryResponse.parse_obj(parsed_response)
            else:
                logger.warning(f"-- No trip summary returned for integration ID: {integration.id}: Vehicle ID {vehicle_id}: {response.text}  --")
                return CTCDetailedTripSummaryResponse()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise CTCUnauthorizedException("Unauthorized access", e)
            if e.response.status_code == 403:
                raise CTCForbiddenException("Forbidden access", e)
            if e.response.status_code == 429:
                raise CTCTooManyRequestsException("Rate Limit reached", e)
            elif e.response.status_code == 500:
                raise CTCInternalServerException("Internal server error", e)
            raise e
