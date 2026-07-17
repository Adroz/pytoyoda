"""Toyota Connected Services API constants."""

# Misc
CLIENT_VERSION = "2.14.0"

# Regions
#
# Each region maps to the set of backend URLs, API key and x-region header
# value used by the myToyota / OneApp mobile app for that market. Values are
# taken directly from the region-specific app builds.
#
# - "EU"  Toyota Europe (b2c-login.toyota-europe.com, realm "tme")
# - "AU"  Toyota Australia (login.toyotadriverslogin.com.au, realm "tmca"),
#         extracted from the "myToyota Connect" app (com.au.toyota.oneapp).
REGIONS = {
    "EU": {
        "base_url": "HTTPS://ctpa-oneapi.tceu-ctp-prd.toyotaconnectedeurope.io",
        "access_token_url": "HTTPS://b2c-login.toyota-europe.com/oauth2/realms/root/realms/tme/access_token",
        "authenticate_url": "HTTPS://b2c-login.toyota-europe.com/json/realms/root/realms/tme/authenticate?authIndexType=service&authIndexValue=oneapp",
        "authorize_url": "HTTPS://b2c-login.toyota-europe.com/oauth2/realms/root/realms/tme/authorize?client_id=oneapp&scope=openid+profile+write&response_type=code&redirect_uri=com.toyota.oneapp:/oauth2Callback&code_challenge=plain&code_challenge_method=plain",
        "api_key": "tTZipv6liF74PwMfk9Ed68AQ0bISswwf3iHQdqcF",
    },
    "AU": {
        "base_url": "HTTPS://tmca-oneapi.telematicsct.com.au",
        # Toyota Australia realm (tmca). The "oneapp" service tree accepts a
        # direct username/password login (same shape as EU's tme "oneapp"
        # tree), so no federated/id_token exchange is required. The edge in
        # front of the host rejects non-app User-Agents, so auth requests must
        # carry the ForgeRock/okhttp headers (see "forgerock_edge").
        "access_token_url": "HTTPS://login.toyotadriverslogin.com.au/oauth2/realms/root/realms/tmca/access_token",
        "authenticate_url": "HTTPS://login.toyotadriverslogin.com.au/json/realms/root/realms/tmca/authenticate?authIndexType=service&authIndexValue=oneapp",
        "authorize_url": "HTTPS://login.toyotadriverslogin.com.au/oauth2/realms/root/realms/tmca/authorize?client_id=oneapp&scope=openid+profile+write&response_type=code&redirect_uri=com.toyota.oneapp:/oauth2Callback&code_challenge=plain&code_challenge_method=plain",
        "api_key": "NADVoTQdLYtnAH68dZY1JIFdeaLNL04VuDgKBse0",
        "forgerock_edge": True,
    },
}

DEFAULT_REGION = "EU"

# Headers required by the ForgeRock AM json/oauth2 endpoints used in the
# federated (AU) flow. The edge in front of login.toyotadriverslogin.com
# rejects non-app User-Agents with a 403, so mimic the app's okhttp client.
FORGEROCK_API_VERSION_HEADER = {
    "Accept-API-Version": "resource=2.1, protocol=1.0",
    "Accept": "application/json",
    "User-Agent": "okhttp/4.10.0",
}
# Basic auth the OneApp ForgeRock SDK sends on the token endpoint (base64 of
# "oneapp:oneapp"), used for both the IdP and tmca token exchanges.
ONEAPP_BASIC_AUTH = "basic b25lYXBwOm9uZWFwcA=="

# API URLs (kept for backwards compatibility; default to the EU region)
API_BASE_URL = REGIONS[DEFAULT_REGION]["base_url"]
ACCESS_TOKEN_URL = REGIONS[DEFAULT_REGION]["access_token_url"]
AUTHENTICATE_URL = REGIONS[DEFAULT_REGION]["authenticate_url"]
AUTHORIZE_URL = REGIONS[DEFAULT_REGION]["authorize_url"]

# Endpoint URLs
CUSTOMER_ACCOUNT_ENDPOINT = "TBD"
VEHICLE_ASSOCIATION_ENDPOINT = "/v1/vehicle-association/vehicle"
VEHICLE_GUID_ENDPOINT = "/v2/vehicle/guid"
VEHICLE_LOCATION_ENDPOINT = "/v1/location"
VEHICLE_HEALTH_STATUS_ENDPOINT = "/v1/vehiclehealth/status"
VEHICLE_GLOBAL_REMOTE_STATUS_ENDPOINT = "/v1/global/remote/status"
VEHICLE_GLOBAL_REMOTE_REFRESH_STATUS_ENDPOINT = "/v1/global/remote/refresh-status"
VEHICLE_GLOBAL_REMOTE_ELECTRIC_STATUS_ENDPOINT = "/v1/global/remote/electric/status"
VEHICLE_GLOBAL_REMOTE_ELECTRIC_REALTIME_STATUS_ENDPOINT = (
    "/v1/global/remote/electric/realtime-status"
)
VEHICLE_GLOBAL_REMOTE_ELECTRIC_CONTROL_ENDPOINT = "/v1/global/remote/electric/command"
VEHICLE_TELEMETRY_ENDPOINT = "/v3/telemetry"
# AU (tmca) serves telemetry at v2 and requires the vehicle "generation"
# header (supplied by models/vehicle.py). The v2 payload maps onto the same
# TelemetryModel fields (odometer, fuelLevel) as EU's v3.
VEHICLE_TELEMETRY_ENDPOINT_AU = "/v2/telemetry"
VEHICLE_NOTIFICATION_HISTORY_ENDPOINT = "/v2/notification/history"
VEHICLE_TRIPS_ENDPOINT = "/v1/trips?from={from_date}&to={to_date}&route={route}&summary={summary}&limit={limit}&offset={offset}"  # noqa: E501
VEHICLE_SERVICE_HISTORY_ENDPONT = "/v1/servicehistory/vehicle/summary"
VEHICLE_CLIMATE_CONTROL_ENDPOINT = "/v1/global/remote/climate-control"
VEHICLE_CLIMATE_SETTINGS_ENDPOINT = "/v1/global/remote/climate-settings"
VEHICLE_CLIMATE_STATUS_ENDPOINT = "/v1/global/remote/climate-status"
VEHICLE_CLIMATE_STATUS_REFRESH_ENDPOINT = "/v1/global/remote/refresh-climate-status"
VEHICLE_COMMAND_ENDPOINT = "/v1/global/remote/command"

# Units
KILOMETERS_UNIT = "km"
MILES_UNIT = "mi"
L_TO_MPG_FACTOR = 235.215
ML_TO_L_FACTOR = 1000.0
ML_TO_GAL_FACTOR = 3785.0
KM_TO_MILES_FACTOR = 0.621371192
MILES_TO_KM_FACTOR = 1.60934
