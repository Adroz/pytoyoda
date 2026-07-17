"""Toyota Connected Services API - Status Models."""

from datetime import datetime

from pydantic import Field

from pytoyoda.models.endpoints.common import StatusModel, UnitValueModel
from pytoyoda.utils.models import CustomEndpointBaseModel


class _ValueStatusModel(CustomEndpointBaseModel):
    value: str | None
    status: int | None


class SectionModel(CustomEndpointBaseModel):
    """Model representing the status category of a vehicle.

    Attributes:
        section (str): The section of a vehicle status category.
        values (list[_ValueStatusModel]): A list of values corresponding
            status informations.

    """

    section: str | None
    values: list[_ValueStatusModel] | None


class VehicleStatusModel(CustomEndpointBaseModel):
    """Model representing the status category of a vehicle.

    Attributes:
        category (str): The status category of the vehicle.
        display_order (int): The order in which the status category is displayed
            inside the MyToyota App.
        sections (list[SectionModel]): The different sections belonging to the category.

    """

    category: str | None
    display_order: int | None = Field(alias="displayOrder")
    sections: list[SectionModel] | None


class _TelemetryModel(CustomEndpointBaseModel):
    fugage: UnitValueModel | None = None
    rage: UnitValueModel | None = None
    odo: UnitValueModel | None


class RemoteStatusModel(CustomEndpointBaseModel):
    """Model representing the remote status of a vehicle.

    Attributes:
        vehicle_status (list[_VehicleStatusModel]): The status of the vehicle.
        telemetry (_TelemetryModel): The telemetry data of the vehicle.
        occurrence_date (datetime): The date of the occurrence.
        caution_overall_count (int): The overall count of cautions.
        latitude (float): The latitude of the vehicle's location.
        longitude (float): The longitude of the vehicle's location.
        location_acquisition_datetime (datetime): The datetime of location acquisition.

    """

    vehicle_status: list[VehicleStatusModel] | None = Field(alias="vehicleStatus")
    telemetry: _TelemetryModel | None
    occurrence_date: datetime | None = Field(alias="occurrenceDate")
    caution_overall_count: int | None = Field(alias="cautionOverallCount")
    latitude: float | None
    longitude: float | None
    location_acquisition_datetime: datetime | None = Field(
        alias="locationAcquisitionDatetime"
    )


class RemoteStatusResponseModel(StatusModel):
    r"""Model representing a remote status response.

    Inherits from StatusModel.

    Attributes:
        payload (Optional[RemoteStatusModel], optional): The remote status payload.
            Defaults to None.

    """

    payload: RemoteStatusModel | None = None


# --- AU (tmca) status normalisation -----------------------------------------
# The AU status endpoint returns the same category/section/values structure as
# EU but with human-readable strings ("Driver Side", "Door", "Locked") instead
# of the i18n keys ("carstatus_category_driver", ...) that LockStatus matches
# on. Section names repeat across categories, so section mapping is scoped per
# (normalised) category. Rewriting the strings in-place lets the existing
# EU-keyed LockStatus mapping work unchanged.
_AU_CATEGORY_MAP = {
    "Driver Side": "carstatus_category_driver",
    "Passenger Side": "carstatus_category_passenger",
    "Other": "carstatus_category_other",
}
_AU_SECTION_MAP = {
    "carstatus_category_driver": {
        "Door": "carstatus_item_driver_door",
        "Rear Door": "carstatus_item_driver_rear_door",
        "Window": "carstatus_item_driver_window",
        "Rear Window": "carstatus_item_driver_rear_window",
    },
    "carstatus_category_passenger": {
        "Door": "carstatus_item_passenger_door",
        "Rear Door": "carstatus_item_passenger_rear_door",
        "Window": "carstatus_item_passenger_window",
        "Rear Window": "carstatus_item_passenger_rear_window",
    },
    "carstatus_category_other": {
        "Hatch": "carstatus_item_rear_hatch",
        "Hood": "carstatus_item_hood",
        "Bonnet": "carstatus_item_hood",
    },
}
_AU_VALUE_MAP = {
    "Closed": "carstatus_closed",
    "Open": "carstatus_closed",
    "Locked": "carstatus_locked",
    "Unlocked": "carstatus_unlocked",
}


def normalize_au_status(model: RemoteStatusResponseModel | None) -> None:
    """Rewrite AU human-readable status strings to EU i18n keys in-place.

    Categories/sections not covered by the maps (e.g. "Trip Details",
    "Hazards") are left unchanged and simply ignored by LockStatus.
    """
    if model is None or model.payload is None or not model.payload.vehicle_status:
        return
    for category in model.payload.vehicle_status:
        mapped_category = _AU_CATEGORY_MAP.get(category.category, category.category)
        section_map = _AU_SECTION_MAP.get(mapped_category, {})
        category.category = mapped_category
        for section in category.sections or []:
            section.section = section_map.get(section.section, section.section)
            for value in section.values or []:
                value.value = _AU_VALUE_MAP.get(value.value, value.value)
