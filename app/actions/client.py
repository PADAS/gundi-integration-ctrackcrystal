import backoff
import httpx
import pydantic
import logging

from datetime import datetime, timezone
from typing import List, Optional


logger = logging.getLogger(__name__)


class UTCNormalizedModel(pydantic.BaseModel):
    @pydantic.root_validator
    def _ensure_datetime_tz(cls, values):
        for k, v in values.items():
            if isinstance(v, datetime) and v.tzinfo is None:
                values[k] = v.replace(tzinfo=timezone.utc)
        return values


class CTCLoginResponse(UTCNormalizedModel):
    jwt: str
    valid_to_utc: datetime = pydantic.Field(..., alias="validToUtc")
    
    class Config:
        allow_population_by_field_name = True

class CTCDevicesList(pydantic.BaseModel):
    id: Optional[str] = None
    unit_type: Optional[str] = pydantic.Field(default=None, alias="unitType")
    hardware_type: Optional[str] = pydantic.Field(default=None, alias="hardwareType")

    class Config:
        allow_population_by_field_name = True


class CTCVehicle(UTCNormalizedModel):
    id: str
    serial_number: str = pydantic.Field(alias="serialNumber")
    display_name: str = pydantic.Field(alias="displayName")
    fleet_number: Optional[str] = pydantic.Field(default=None, alias="fleetNumber")
    registration_number: Optional[str] = pydantic.Field(default=None, alias="registrationNumber")
    vin: Optional[str] = None
    make: Optional[str] = None
    model: Optional[str] = None
    color: Optional[str] = None
    driver_id: Optional[str] = pydantic.Field(default=None, alias="driverId")
    odometer: Optional[int] = None
    running_hours: Optional[int] = pydantic.Field(default=None, alias="runningHours")
    first_start_up_time: Optional[datetime] = pydantic.Field(default=None, alias="firstStartUpTime")
    last_reported_time: Optional[datetime] = pydantic.Field(default=None, alias="lastReportedTime")
    devices_list: Optional[List[CTCDevicesList]] = pydantic.Field(default=None, alias="devicesList")

    class Config:
        allow_population_by_field_name = True


class CTCTripDetail(UTCNormalizedModel):
    date: datetime
    trip_id: str = pydantic.Field(alias="tripId")
    trip_start_time: Optional[datetime] = pydantic.Field(default=None, alias="tripStartTime")
    trip_end_time: Optional[datetime] = pydantic.Field(default=None, alias="tripendTime")
    distance_driven: Optional[float] = pydantic.Field(default=None, alias="distanceDriven")
    current_distance: Optional[float] = pydantic.Field(default=None, alias="currentDistance")
    running_distance: Optional[float] = pydantic.Field(default=None, alias="runningDistance")
    running_duration: Optional[float] = pydantic.Field(default=None, alias="runningDuration")
    drive_time: Optional[float] = pydantic.Field(default=None, alias="driveTime")
    idle_time: Optional[float] = pydantic.Field(default=None, alias="idleTime")
    max_speed: Optional[float] = pydantic.Field(default=None, alias="maxSpeed")
    stop_time: Optional[float] = pydantic.Field(default=None, alias="stopTime")
    trip_mode: Optional[str] = pydantic.Field(default=None, alias="tripMode")
    trip_start_latitude: Optional[str] = pydantic.Field(default=None, alias="tripStartLatitude")
    trip_start_longitude: Optional[str] = pydantic.Field(default=None, alias="tripStartLongitude")
    trip_end_latitude: Optional[str] = pydantic.Field(default=None, alias="tripEndLatitude")
    trip_end_longitude: Optional[str] = pydantic.Field(default=None, alias="tripEndLongitude")
    start_location_detail: Optional[str] = pydantic.Field(default=None, alias="startLocationDetail")
    end_location_detail: Optional[str] = pydantic.Field(default=None, alias="endLocationDetail")

    class Config:
        allow_population_by_field_name = True


class CTCTrip(pydantic.BaseModel):
    id: str
    trip_count: Optional[int] = pydantic.Field(default=None, alias="tripCount")
    total_distance: Optional[float] = pydantic.Field(default=None, alias="totalDistance")
    total_stop_time: Optional[float] = pydantic.Field(default=None, alias="totalStopTime")
    total_idle_time: Optional[float] = pydantic.Field(default=None, alias="totalIdleTime")
    total_drive_time: Optional[float] = pydantic.Field(default=None, alias="totalDriveTime")
    total_violation_count: Optional[float] = pydantic.Field(default=None, alias="totalViolationCount")
    max_speed: Optional[float] = pydantic.Field(default=None, alias="maxSpeed")
    average_daily_distance: Optional[float] = pydantic.Field(default=None, alias="averageDailyDistance")
    average_vehicle_distance: Optional[float] = pydantic.Field(default=None, alias="averageVehicleDistance")
    details: List[CTCTripDetail]

    class Config:
        allow_population_by_field_name = True


class CTCLocationSummary(UTCNormalizedModel):
    event_id: Optional[int] = pydantic.Field(default=None, alias="eventId")
    event_time: datetime = pydantic.Field(alias="eventTime")
    event_text: Optional[str] = pydantic.Field(default=None, alias="eventText")
    latitude: float
    longitude: float
    speed: Optional[float] = None
    distance: Optional[float] = None
    heading: Optional[int] = None
    direction: Optional[str] = None
    running_distance: Optional[float] = pydantic.Field(default=None, alias="runningDistance")

    class Config:
        allow_population_by_field_name = True


class CTCDetailedTripSummaryResponse(pydantic.BaseModel):
    location_summary: List[CTCLocationSummary] = pydantic.Field(default_factory=list, alias="locationSummary")

    class Config:
        allow_population_by_field_name = True


class CTCTripsResponse(pydantic.BaseModel):
    count: int = 0
    payload: List[CTCTrip] = pydantic.Field(default_factory=list)


class CTCGetVehiclesResponse(pydantic.BaseModel):
    count: int = 0
    vehicles: List[CTCVehicle] = pydantic.Field(default_factory=list)


class CTCBaseException(Exception):
    def __init__(self, message: str, error: Exception = None, status_code: int = None):
        self.status_code = status_code
        self.message = message
        self.error = error
        super().__init__(f"'{self.status_code}: {self.message}, Error: {self.error}'")


class CTCTooManyRequestsException(CTCBaseException):
    def __init__(self, message: str, error: Exception = None, status_code=429):
        super().__init__(message, error, status_code)


class CTCNotFoundException(CTCBaseException):
    def __init__(self, message: str, error: Exception = None, status_code=404):
        super().__init__(message, error, status_code)


class CTCUnauthorizedException(CTCBaseException):
    def __init__(self, message: str, error: Exception = None, status_code=401):
        super().__init__(message, error, status_code)


class CTCForbiddenException(CTCBaseException):
    def __init__(self, message: str, error: Exception = None, status_code=403):
        super().__init__(message, error, status_code)


class CTCInternalServerException(CTCBaseException):
    def __init__(self, message: str, error: Exception = None, status_code=500):
        super().__init__(message, error, status_code)


def _get_retry_after(exc):
    """Extract Retry-After header value in seconds from exception."""
    retry_after = 0
    try:
        retry_after_header = exc.error.response.headers.get("Retry-After")
        if retry_after_header:
            retry_after = int(retry_after_header)
    except Exception:
        retry_after = 10
    return retry_after


def make_retry_after_wait_gen():
    last_exc = {"exc": None}
    def on_backoff(details):
        last_exc["exc"] = details["exception"]
    def wait_gen():
        while True:
            exc = last_exc["exc"]
            yield _get_retry_after(exc) if exc else 10
    return wait_gen, on_backoff


wait_gen, on_backoff_cb = make_retry_after_wait_gen()


@backoff.on_exception(
    wait_gen=wait_gen,
    exception=CTCTooManyRequestsException,
    max_tries=3,
    jitter=None,
    on_backoff=on_backoff_cb
)
async def get_token(
        base_url: str,
        username: str,
        password: pydantic.SecretStr,
        subscription_key: pydantic.SecretStr
) -> CTCLoginResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
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
                logger.warning(f"-- Get token failed for username: {username}: {response.text}  --")
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
    wait_gen=wait_gen,
    exception=CTCTooManyRequestsException,
    max_tries=3,
    jitter=None,
    on_backoff=on_backoff_cb
)
async def refresh_token(
        base_url: str,
        token: str,
        subscription_key: pydantic.SecretStr
) -> CTCLoginResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
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
    wait_gen=wait_gen,
    exception=CTCTooManyRequestsException,
    max_tries=3,
    jitter=None,
    on_backoff=on_backoff_cb
)
async def get_vehicles(
        token: str,
        subscription_key: pydantic.SecretStr,
        base_url: str
) -> CTCGetVehiclesResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        url = f"{base_url}/Vehicle/GetVehicles"

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value(),
            "x-token": token
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
    wait_gen=wait_gen,
    exception=CTCTooManyRequestsException,
    max_tries=3,
    jitter=None,
    on_backoff=on_backoff_cb
)
async def get_vehicle_trips(
        token: str,
        subscription_key: pydantic.SecretStr,
        base_url: str,
        vehicle_id: str,
        filter_day: datetime
) -> CTCTripsResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        url = f"{base_url}/Vehicle/Trips"

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value(),
            "x-token": token
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
    wait_gen=wait_gen,
    exception=CTCTooManyRequestsException,
    max_tries=3,
    jitter=None,
    on_backoff=on_backoff_cb
)
async def get_trip_summary(
        token: str,
        subscription_key: pydantic.SecretStr,
        base_url: str,
        trip_id: str
) -> CTCDetailedTripSummaryResponse:
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=30.0, write=15.0, pool=5.0)) as session:
        url = f"{base_url}/Vehicle/DetailedTripSummary/{trip_id}"

        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key.get_secret_value(),
            "x-token": token
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
