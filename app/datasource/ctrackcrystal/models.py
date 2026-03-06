"""Pydantic models for Ctrack Crystal API responses."""

from datetime import datetime, timezone
from typing import List, Optional

import pydantic


class UTCNormalizedModel(pydantic.BaseModel):
    @pydantic.root_validator
    def _ensure_datetime_tz(cls, values):
        for k, v in values.items():
            if isinstance(v, datetime) and v.tzinfo is None:
                values[k] = v.replace(tzinfo=timezone.utc)
        return values


# --- Auth ---


class LoginResponse(UTCNormalizedModel):
    jwt: str
    valid_to_utc: datetime = pydantic.Field(..., alias="validToUtc")

    class Config:
        allow_population_by_field_name = True


# --- Vehicles ---


class DevicesList(pydantic.BaseModel):
    id: Optional[str] = None
    unit_type: Optional[str] = pydantic.Field(default=None, alias="unitType")
    hardware_type: Optional[str] = pydantic.Field(default=None, alias="hardwareType")

    class Config:
        allow_population_by_field_name = True


class Vehicle(UTCNormalizedModel):
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
    devices_list: Optional[List[DevicesList]] = pydantic.Field(default=None, alias="devicesList")

    class Config:
        allow_population_by_field_name = True


class GetVehiclesResponse(pydantic.BaseModel):
    count: int = 0
    vehicles: List[Vehicle] = pydantic.Field(default_factory=list)


# --- Trips ---


class TripDetail(UTCNormalizedModel):
    date: datetime
    trip_id: str = pydantic.Field(alias="tripId")
    trip_start_time: Optional[datetime] = pydantic.Field(default=None, alias="tripStartTime")
     
    # the alias casing is intentional here based on live samples from the API.
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
    start_location_detail: Optional[dict] = pydantic.Field(default=None, alias="startLocationDetail")
    end_location_detail: Optional[dict] = pydantic.Field(default=None, alias="endLocationDetail")

    class Config:
        allow_population_by_field_name = True


class Trip(pydantic.BaseModel):
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
    details: List[TripDetail]

    class Config:
        allow_population_by_field_name = True


class TripsResponse(pydantic.BaseModel):
    count: int = 0
    payload: List[Trip] = pydantic.Field(default_factory=list)


# --- Detailed trip summary (GPS locations) ---


class LocationSummary(UTCNormalizedModel):
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


class DetailedTripSummaryResponse(pydantic.BaseModel):
    location_summary: List[LocationSummary] = pydantic.Field(
        default_factory=list, alias="locationSummary"
    )

    @pydantic.validator("location_summary", pre=True)
    def _coerce_null_location_summary(cls, v):
        if v is None:
            return []
        return v

    class Config:
        allow_population_by_field_name = True
