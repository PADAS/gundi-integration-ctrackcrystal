"""Ctrack Crystal API client: auth, vehicles, trips, detailed trip summary."""

from .client import (
    DEFAULT_TIMEOUT,
    get_detailed_trip_summary,
    get_trips,
    get_vehicles,
    login,
    refresh_token,
)
from .exceptions import (
    ClientBaseException,
    ForbiddenException,
    InternalServerException,
    ReadTimeoutException,
    UnauthorizedException,
    TooManyRequestsException,
)
from .models import (
    DetailedTripSummaryResponse,
    GetVehiclesResponse,
    LocationSummary,
    LoginResponse,
    Trip,
    TripDetail,
    TripsResponse,
    Vehicle,
)

# Default base URL for Ctrack Crystal API (caller may override).
BASE_URL = "https://apim.ctrackcrystal.com"

__all__ = [
    "BASE_URL",
    "DEFAULT_TIMEOUT",
    "ClientBaseException",
    "DetailedTripSummaryResponse",
    "ForbiddenException",
    "GetVehiclesResponse",
    "InternalServerException",
    "LocationSummary",
    "LoginResponse",
    "ReadTimeoutException",
    "Trip",
    "TripDetail",
    "TripsResponse",
    "UnauthorizedException",
    "Vehicle",
    "TooManyRequestsException",
    "get_detailed_trip_summary",
    "get_trips",
    "get_vehicles",
    "login",
    "refresh_token",
]
