"""HTTP client for Ctrack Crystal API with retries for 429, 5xx, and ReadTimeout."""

import logging
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Optional

import backoff
import httpx

from .exceptions import (
    ClientBaseException,
    ForbiddenException,
    InternalServerException,
    ReadTimeoutException,
    TooManyRequestsException,
    UnauthorizedException,
)
from .models import (
    DetailedTripSummaryResponse,
    GetVehiclesResponse,
    LoginResponse,
    TripsResponse,
)

logger = logging.getLogger(__name__)

# Read timeout: Trip and DetailedTripSummary endpoints can be slow.
DEFAULT_TIMEOUT = httpx.Timeout(5.0, read=90.0)
SERVER_ERROR_BACKOFF_SECONDS = 15
MAX_TRIES = 3


def _handle_httpx_error(e: httpx.HTTPStatusError) -> None:
    status = e.response.status_code
    if status == 401:
        raise UnauthorizedException("Unauthorized access", e) from e
    if status == 403:
        raise ForbiddenException("Forbidden access", e) from e
    if status == 429:
        raise TooManyRequestsException("Rate Limit reached", e) from e
    if status in (500, 502, 503, 504):
        raise InternalServerException(
            f"Server error ({status})",
            e,
            status_code=status,
        ) from e
    raise e


def _get_retry_after(exc: ClientBaseException) -> int:
    """Extract Retry-After header value in seconds. RFC 7231 delay-seconds or HTTP-date."""
    if exc is None:
        return 10
    default = 10
    if not getattr(exc, "error", None) or not getattr(exc.error, "response", None):
        return default
    try:
        raw = exc.error.response.headers.get("Retry-After")
        if not raw:
            return default
        raw = raw.strip()
        try:
            return max(1, int(raw))
        except ValueError:
            parsed = parsedate_to_datetime(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            delta = (parsed - datetime.now(timezone.utc)).total_seconds()
            return int(max(1, delta)) if delta > 0 else default
    except Exception:
        return default


def _wait_seconds_for_exception(exc: Exception) -> int:
    """Return wait time in seconds: Retry-After for 429, fixed delay for 5xx and ReadTimeout."""
    if exc is None:
        return 10
    if isinstance(exc, (InternalServerException, ReadTimeoutException)):
        return SERVER_ERROR_BACKOFF_SECONDS
    if isinstance(exc, TooManyRequestsException):
        return _get_retry_after(exc)  # type: ignore[arg-type]
    return 10


def _retry_after_wait_gen():
    """Generator for backoff: receives the exception via .send(exception)."""
    exc = None
    while True:
        wait = _wait_seconds_for_exception(exc)
        exc = yield wait


def _on_retry_backoff(details: dict) -> None:
    wait = details.get("wait", 10)
    tries = details.get("tries", 0)
    exc = details.get("exception")
    if exc is not None and isinstance(exc, ReadTimeoutException):
        logger.warning(
            "Read timeout from Ctrack Crystal API, retrying in %ss (attempt %s/%s)",
            wait, tries, MAX_TRIES,
        )
    elif exc is not None and isinstance(exc, InternalServerException):
        logger.warning(
            "Server error (%s) from Ctrack Crystal API, retrying in %ss (attempt %s/%s)",
            getattr(exc, "status_code", "5xx"), wait, tries, MAX_TRIES,
        )
    else:
        logger.warning(
            "Rate limit (429) from Ctrack Crystal API, retrying in %ss (attempt %s/%s)",
            wait, tries, MAX_TRIES,
        )


_RETRY_EXCEPTIONS = (TooManyRequestsException, InternalServerException, ReadTimeoutException)


def _maybe_raise_read_timeout(exc: httpx.ReadTimeout) -> None:
    raise ReadTimeoutException("Read timeout", exc) from exc


@backoff.on_exception(
    wait_gen=_retry_after_wait_gen,
    exception=_RETRY_EXCEPTIONS,
    max_tries=MAX_TRIES,
    jitter=None,
    on_backoff=_on_retry_backoff,
)
async def login(
    base_url: str,
    username: str,
    password: str,
    subscription_key: str,
    *,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> Optional[LoginResponse]:
    """Authenticate and return login response (caller caches token)."""
    async with httpx.AsyncClient(timeout=timeout) as session:
        url = f"{base_url}/api/Authenticate/Login"
        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key,
        }
        body = {"username": username, "password": password}
        try:
            response = await session.post(url, json=body, headers=headers)
            if response.is_error:
                logger.error("Error in 'login' endpoint. Response body: %s", response.text)
            response.raise_for_status()
            data = response.json()
            if data:
                return LoginResponse.parse_obj(data)
            logger.warning("Login failed for username %s: %s", username, response.text)
            return None
        except httpx.ReadTimeout as e:
            _maybe_raise_read_timeout(e)
        except httpx.HTTPStatusError as e:
            _handle_httpx_error(e)


@backoff.on_exception(
    wait_gen=_retry_after_wait_gen,
    exception=_RETRY_EXCEPTIONS,
    max_tries=MAX_TRIES,
    jitter=None,
    on_backoff=_on_retry_backoff,
)
async def refresh_token(
    base_url: str,
    token: str,
    subscription_key: str,
    *,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> Optional[LoginResponse]:
    """Refresh JWT (caller stores new token)."""
    async with httpx.AsyncClient(timeout=timeout) as session:
        url = f"{base_url}/api/Authenticate/RefreshToken"
        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key,
            "x-token": token,
        }
        try:
            response = await session.post(url, headers=headers)
            if response.is_error:
                logger.error("Error in 'refresh_token' endpoint. Response body: %s", response.text)
            response.raise_for_status()
            data = response.json()
            if data:
                return LoginResponse.parse_obj(data)
            return None
        except httpx.ReadTimeout as e:
            _maybe_raise_read_timeout(e)
        except httpx.HTTPStatusError as e:
            _handle_httpx_error(e)


@backoff.on_exception(
    wait_gen=_retry_after_wait_gen,
    exception=_RETRY_EXCEPTIONS,
    max_tries=MAX_TRIES,
    jitter=None,
    on_backoff=_on_retry_backoff,
)
async def get_vehicles(
    base_url: str,
    token: str,
    subscription_key: str,
    *,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> GetVehiclesResponse:
    """Fetch all vehicles; use lastReportedTime to decide which need trip data."""
    async with httpx.AsyncClient(timeout=timeout) as session:
        url = f"{base_url}/api/Vehicle/GetVehicles"
        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key,
            "x-token": token,
        }
        try:
            response = await session.get(url, headers=headers)
            if response.is_error:
                logger.error("Error in 'get_vehicles' endpoint. Response body: %s", response.text)
            response.raise_for_status()
            data = response.json()
            if data:
                return GetVehiclesResponse.parse_obj(data)
            return GetVehiclesResponse()
        except httpx.ReadTimeout as e:
            _maybe_raise_read_timeout(e)
        except httpx.HTTPStatusError as e:
            _handle_httpx_error(e)


@backoff.on_exception(
    wait_gen=_retry_after_wait_gen,
    exception=_RETRY_EXCEPTIONS,
    max_tries=MAX_TRIES,
    jitter=None,
    on_backoff=_on_retry_backoff,
)
async def get_trips(
    base_url: str,
    token: str,
    subscription_key: str,
    vehicle_ids: List[str],
    filter_day: date,
    *,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> TripsResponse:
    """Fetch trips for the given vehicle ids on the given UTC calendar day (batch)."""
    if not vehicle_ids:
        return TripsResponse()
    async with httpx.AsyncClient(timeout=timeout) as session:
        url = f"{base_url}/api/Vehicle/Trips"
        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key,
            "x-token": token,
        }
        params = {"filterDay": filter_day.strftime("%Y-%m-%d")}
        body = {"ids": vehicle_ids}
        try:
            response = await session.post(url, headers=headers, params=params, json=body)
            if response.is_error:
                logger.error("Error in 'get_trips' endpoint. Response body: %s", response.text)
            response.raise_for_status()
            data = response.json()
            if data:
                return TripsResponse.parse_obj(data)
            return TripsResponse()
        except httpx.ReadTimeout as e:
            _maybe_raise_read_timeout(e)
        except httpx.HTTPStatusError as e:
            _handle_httpx_error(e)


@backoff.on_exception(
    wait_gen=_retry_after_wait_gen,
    exception=_RETRY_EXCEPTIONS,
    max_tries=MAX_TRIES,
    jitter=None,
    on_backoff=_on_retry_backoff,
)
async def get_detailed_trip_summary(
    base_url: str,
    token: str,
    subscription_key: str,
    trip_id: str,
    *,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> DetailedTripSummaryResponse:
    """Fetch locationSummary (GPS points) for a trip."""
    async with httpx.AsyncClient(timeout=timeout) as session:
        url = f"{base_url}/api/Vehicle/DetailedTripSummary/{trip_id}"
        headers = {
            "Content-Type": "application/json",
            "Ocp-Apim-Subscription-Key": subscription_key,
            "x-token": token,
        }
        try:
            response = await session.get(url, headers=headers)
            if response.is_error:
                logger.error(
                    "Error in 'get_detailed_trip_summary' endpoint. Response body: %s",
                    response.text,
                )
            response.raise_for_status()
            data = response.json()
            if data:
                return DetailedTripSummaryResponse.parse_obj(data)
            return DetailedTripSummaryResponse()
        except httpx.ReadTimeout as e:
            _maybe_raise_read_timeout(e)
        except httpx.HTTPStatusError as e:
            _handle_httpx_error(e)
