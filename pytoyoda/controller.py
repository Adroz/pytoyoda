"""Toyota Connected Services Controller."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import ssl
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, ClassVar
from urllib import parse
from uuid import uuid4

import httpx
import jwt
from hishel.httpx import AsyncCacheClient
from loguru import logger

from pytoyoda.const import (
    CLIENT_VERSION,
    DEFAULT_REGION,
    FORGEROCK_API_VERSION_HEADER,
    ONEAPP_BASIC_AUTH,
    REGIONS,
)
from pytoyoda.exceptions import (
    ToyotaApiError,
    ToyotaInternalError,
    ToyotaInvalidUsernameError,
    ToyotaLoginError,
)
from pytoyoda.utils.helpers import generate_hmac_sha256
from pytoyoda.utils.log_utils import format_httpx_response

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


@dataclass
class TokenInfo:
    """Class to store token information."""

    access_token: str
    refresh_token: str
    uuid: str
    expiration: datetime


class Controller:
    """Controller class for Toyota Connected Services."""

    # Class variable for token cache
    _TOKEN_CACHE: ClassVar[dict[str, TokenInfo]] = {}

    def __init__(
        self,
        username: str,
        password: str,
        brand: str = "T",
        timeout: int = 60,
        region: str = DEFAULT_REGION,
    ) -> None:
        """Initialize Controller class.

        Args:
            username: Toyota account username
            password: Toyota account password
            brand: Brand of the car (T for Toyota, L for Lexus)
            timeout: HTTP request timeout in seconds
            region: Toyota region to connect to (e.g. "EU", "AU")

        Raises:
            ValueError: If the region is not supported

        """
        self._username: str = username
        self._password: str = password
        self._brand: str = brand
        self._timeout = timeout

        if region not in REGIONS:
            supported = ", ".join(sorted(REGIONS))
            msg = f"Unsupported region '{region}'. Supported regions: {supported}."
            raise ValueError(msg)
        self._region: str = region
        region_config = REGIONS[region]
        self._api_key: str = region_config["api_key"]

        # URLs
        self._api_base_url = httpx.URL(region_config["base_url"])
        self._access_token_url = httpx.URL(region_config["access_token_url"])
        self._authenticate_url = httpx.URL(region_config["authenticate_url"])
        self._authorize_url = httpx.URL(region_config["authorize_url"])

        # Federated login (stage 1 on a separate IdP realm to mint an id_token
        # exchanged via IDTokenAuth). Not used by the current regions, kept for
        # markets that require it. EU/AU both use a direct single-realm flow.
        self._federated: bool = region_config.get("federated", False)
        self._idp: dict[str, str] | None = region_config.get("idp")

        # Some regions (AU) sit behind an edge that rejects non-app requests;
        # send the ForgeRock/okhttp headers on every auth request there.
        self._auth_headers: dict[str, str] | None = (
            FORGEROCK_API_VERSION_HEADER
            if region_config.get("forgerock_edge")
            else None
        )

        # Authentication state
        self._token_info: TokenInfo | None = None

        # Reused httpx.AsyncClient for data requests. Lazily constructed inside
        # an async context and kept for the lifetime of the Controller, so that
        # SSL context + TCP connection pool survive across request_raw calls.
        self._client: httpx.AsyncClient | None = None

        # Cached SSL context shared by every AsyncClient this Controller builds.
        # ssl.create_default_context() reads the CA bundle from disk
        # synchronously, which trips Home Assistant's blocking-call watchdog
        # when called from the event loop (one warning per AsyncClient
        # construction). We build it once in an executor and reuse.
        self._ssl_ctx: ssl.SSLContext | None = None

        # Load from cache if available
        if self._username in self._TOKEN_CACHE:
            self._token_info = self._TOKEN_CACHE[self._username]

    @property
    def _token(self) -> str | None:
        """Get the current access token."""
        return self._token_info.access_token if self._token_info else None

    @property
    def _refresh_token(self) -> str | None:
        """Get the current refresh token."""
        return self._token_info.refresh_token if self._token_info else None

    @property
    def _uuid(self) -> str | None:
        """Get the current UUID."""
        return self._token_info.uuid if self._token_info else None

    @property
    def _token_expiration(self) -> datetime | None:
        """Get the token expiration datetime."""
        return self._token_info.expiration if self._token_info else None

    def _is_token_valid(self) -> bool:
        """Check if the current token is valid and not expired."""
        if not self._token_info:
            return False
        return self._token_info.expiration > datetime.now(timezone.utc)

    async def login(self) -> None:
        """Perform initial login if necessary."""
        if not self._is_token_valid():
            await self._update_token()

    async def _update_token(self) -> None:
        """Update the authentication token.

        First tries to refresh the token if available, falls back to
        full authentication.

        """
        if not self._is_token_valid():
            if self._refresh_token:
                try:
                    await self._refresh_tokens()
                except ToyotaLoginError:
                    logger.debug(
                        "Token refresh failed, falling back to full authentication"
                    )
                else:
                    return

            await self._authenticate()

    async def _get_ssl_context(self) -> ssl.SSLContext:
        """Return a cached SSL context, building it off the event loop on first use.

        httpx.create_ssl_context() reads the CA bundle synchronously, which
        blocks the event loop for ~1-10ms and trips Home Assistant's
        blocking-call watchdog. By caching the context on the Controller and
        sharing it across AsyncClient constructions, we pay that cost once
        per Controller lifetime instead of per HTTP client.
        """
        if self._ssl_ctx is None:
            loop = asyncio.get_running_loop()
            self._ssl_ctx = await loop.run_in_executor(None, httpx.create_ssl_context)
        return self._ssl_ctx

    @asynccontextmanager
    async def _get_http_client(self) -> AsyncGenerator:
        """Context manager for HTTP client with consistent timeout."""
        ssl_ctx = await self._get_ssl_context()
        async with AsyncCacheClient(timeout=self._timeout, verify=ssl_ctx) as client:
            yield client

    async def _authenticate(self) -> None:
        """Authenticate with username and password."""
        logger.debug("Authenticating with username and password")

        async with self._get_http_client() as client:
            if self._federated:
                await self._authenticate_federated(client)
                return

            # Authentication flow
            auth_data = await self._perform_authentication(client)

            # Authorization flow
            auth_code = await self._perform_authorization(client, auth_data["tokenId"])

            # Token retrieval
            token_data = await self._retrieve_tokens(client, auth_code)

            # Update tokens
            self._update_tokens(token_data)

    @staticmethod
    def _generate_pkce_s256() -> tuple[str, str]:
        """Generate an S256 PKCE (code_verifier, code_challenge) pair.

        Matches the ForgeRock Android SDK: verifier is url-safe base64 without
        padding, challenge is url-safe base64 (no padding) of SHA-256(verifier).
        """
        verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        )
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        return verifier, challenge

    async def _authenticate_federated(self, client: AsyncCacheClient) -> None:
        """Perform the AU-style federated (2-realm) login.

        Stage 1: username/password against the IdP realm (tmna-native) to mint
        an id_token. Stage 2: exchange that id_token via the region's
        IDTokenAuth tree for a session. Stage 3-4: authorize + token against the
        region realm (tmca) to obtain the bearer used for data requests.
        """
        idp = self._idp
        if idp is None:
            msg = "Federated login requested but no IdP config for region."
            raise ToyotaLoginError(msg)

        logger.debug("Federated login: stage 1 (IdP username/password)")
        idp_auth = await self._perform_authentication(
            client,
            authenticate_url=httpx.URL(idp["authenticate_url"]),
            extra_headers=FORGEROCK_API_VERSION_HEADER,
        )

        verifier, challenge = self._generate_pkce_s256()
        idp_code = await self._perform_authorization_pkce(
            client,
            token_id=idp_auth["tokenId"],
            authorize_url=httpx.URL(idp["authorize_url"]),
            client_id=idp["client_id"],
            scope=idp["scope"],
            redirect_uri=idp["redirect_uri"],
            code_challenge=challenge,
        )
        idp_tokens = await self._retrieve_tokens_generic(
            client,
            auth_code=idp_code,
            token_url=httpx.URL(idp["access_token_url"]),
            client_id=idp["client_id"],
            redirect_uri=idp["redirect_uri"],
            code_verifier=verifier,
        )
        id_token = idp_tokens.get("id_token")
        if not id_token:
            msg = "Federated login: IdP stage returned no id_token."
            raise ToyotaLoginError(msg)

        logger.debug("Federated login: stage 2 (IDTokenAuth exchange)")
        tmca_auth = await self._perform_idtoken_exchange(client, id_token)

        logger.debug("Federated login: stage 3-4 (tmca authorize + token)")
        auth_code = await self._perform_authorization(client, tmca_auth["tokenId"])
        token_data = await self._retrieve_tokens(client, auth_code)
        self._update_tokens(token_data)

    async def _perform_authorization_pkce(  # noqa: PLR0913
        self,
        client: AsyncCacheClient,
        token_id: str,
        authorize_url: httpx.URL,
        client_id: str,
        scope: str,
        redirect_uri: str,
        code_challenge: str,
    ) -> list[str]:
        """Authorize with an explicit S256 PKCE challenge (federated stage 1)."""
        resp = await client.get(
            authorize_url,
            params={
                "client_id": client_id,
                "scope": scope,
                "response_type": "code",
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            },
            headers={
                "cookie": f"iPlanetDirectoryPro={token_id}",
                **FORGEROCK_API_VERSION_HEADER,
            },
        )
        logger.debug(format_httpx_response(resp))

        if resp.status_code != HTTPStatus.FOUND:
            msg = f"Authorization (IdP) failed. {resp.status_code}, {resp.text}."
            raise ToyotaLoginError(msg)

        return parse.parse_qs(httpx.URL(resp.headers.get("location")).query.decode())[
            "code"
        ]

    async def _retrieve_tokens_generic(  # noqa: PLR0913
        self,
        client: AsyncCacheClient,
        auth_code: list[str],
        token_url: httpx.URL,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        """Exchange an auth code for tokens against an arbitrary realm."""
        resp = await client.post(
            token_url,
            headers={
                "authorization": ONEAPP_BASIC_AUTH,
                **FORGEROCK_API_VERSION_HEADER,
            },
            data={
                "client_id": client_id,
                "code": auth_code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
        )
        logger.debug(format_httpx_response(resp))

        if resp.status_code != HTTPStatus.OK:
            msg = f"Token retrieval (IdP) failed. {resp.status_code}, {resp.text}."
            raise ToyotaLoginError(msg)

        return resp.json()

    async def _perform_idtoken_exchange(
        self, client: AsyncCacheClient, id_token: str
    ) -> dict[str, Any]:
        """Exchange an IdP id_token for a region session via IDTokenAuth.

        Posts an empty body to the region's IDTokenAuth tree to fetch its
        callback template, injects the id_token, and resubmits to obtain the
        region ``tokenId``. The exact callback shape is logged so it can be
        adapted if the tree differs from the assumed single-input callback.
        """
        data: dict[str, Any] = {}

        for _ in range(10):
            if "callbacks" in data:
                injected = False
                for cb in data["callbacks"]:
                    # The IDTokenAuth tree expects the id_token in an input
                    # callback. Fill the first callback that exposes an input.
                    if cb.get("input"):
                        cb["input"][0]["value"] = id_token
                        injected = True
                        break
                if not injected:
                    logger.warning(
                        "IDTokenAuth: no input callback to inject id_token; "
                        "callbacks={}",
                        data.get("callbacks"),
                    )

            resp = await client.post(
                self._authenticate_url,
                json=data,
                headers=FORGEROCK_API_VERSION_HEADER,
            )
            logger.debug(format_httpx_response(resp))

            if resp.status_code != HTTPStatus.OK:
                msg = (
                    f"IDTokenAuth exchange failed. {resp.status_code}, {resp.text}."
                )
                raise ToyotaLoginError(msg)

            data = resp.json()
            if "callbacks" in data:
                logger.debug("IDTokenAuth callbacks: {}", data["callbacks"])
            if "tokenId" in data:
                return data

        msg = "IDTokenAuth exchange failed. Token ID not received."
        raise ToyotaLoginError(msg)

    async def _perform_authentication(
        self,
        client: AsyncCacheClient,
        authenticate_url: httpx.URL | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Perform the username/password authentication part of the login flow.

        Args:
            client: HTTP client
            authenticate_url: Override authenticate endpoint (defaults to the
                region's tme/tmca URL). The federated IdP stage passes the
                tmna-native URL here.
            extra_headers: Additional headers (e.g. the ForgeRock
                Accept-API-Version header required by the IdP realm).

        """
        url = authenticate_url or self._authenticate_url
        # The IdP (tmna-native) tree prompts differ from the EU tree, so match
        # NameCallback/PasswordCallback by type rather than by prompt text.
        lenient = authenticate_url is not None
        data: dict[str, Any] = {}

        for _ in range(10):  # Try up to 10 times
            if "callbacks" in data:
                for cb in data["callbacks"]:
                    is_name = cb["type"] == "NameCallback" and (
                        lenient or cb["output"][0]["value"] == "User Name"
                    )
                    if is_name:
                        cb["input"][0]["value"] = self._username
                    elif cb["type"] == "PasswordCallback":
                        cb["input"][0]["value"] = self._password
                    elif (
                        cb["type"] == "TextOutputCallback"
                        and cb["output"][0]["value"] == "User Not Found"
                    ):
                        msg = "Authentication Failed. User Not Found."
                        raise ToyotaInvalidUsernameError(msg)

            resp = await client.post(
                url, json=data, headers=extra_headers or self._auth_headers
            )
            logger.debug(format_httpx_response(resp))

            if resp.status_code != HTTPStatus.OK:
                msg = f"Authentication Failed. {resp.status_code}, {resp.text}."
                raise ToyotaLoginError(msg)

            data = resp.json()

            # Wait for tokenId to be returned in response
            if "tokenId" in data:
                return data

        msg = "Authentication Failed. Token ID not received after multiple attempts."
        raise ToyotaLoginError(msg)

    async def _perform_authorization(
        self, client: AsyncCacheClient, token_id: str
    ) -> list[str]:
        """Perform the authorization part of the login flow.

        Args:
            client: HTTP client
            token_id: Token ID from authentication

        Returns:
            Authentication code

        """
        resp = await client.get(
            self._authorize_url,
            headers={
                "cookie": f"iPlanetDirectoryPro={token_id}",
                **(self._auth_headers or {}),
            },
        )
        logger.debug(format_httpx_response(resp))

        if resp.status_code != HTTPStatus.FOUND:
            msg = f"Authorization failed. {resp.status_code}, {resp.text}."
            raise ToyotaLoginError(msg)

        return parse.parse_qs(httpx.URL(resp.headers.get("location")).query.decode())[
            "code"
        ]

    async def _retrieve_tokens(
        self, client: AsyncCacheClient, auth_code: list[str]
    ) -> dict[str, Any]:
        """Retrieve access and refresh tokens.

        Args:
            client: HTTP client
            auth_code: Authorization code

        Returns:
            Token response data

        """
        resp = await client.post(
            self._access_token_url,
            headers={
                "authorization": "basic b25lYXBwOm9uZWFwcA==",
                **(self._auth_headers or {}),
            },
            data={
                "client_id": "oneapp",
                "code": auth_code,
                "redirect_uri": "com.toyota.oneapp:/oauth2Callback",
                "grant_type": "authorization_code",
                "code_verifier": "plain",
            },
        )
        logger.debug(format_httpx_response(resp))

        if resp.status_code != HTTPStatus.OK:
            msg = f"Token retrieval failed. {resp.status_code}, {resp.text}."
            raise ToyotaLoginError(msg)

        return resp.json()

    async def _refresh_tokens(self) -> None:
        """Refresh the access token using the refresh token."""
        logger.debug("Refreshing tokens")

        async with self._get_http_client() as client:
            resp = await client.post(
                self._access_token_url,
                headers={"authorization": "basic b25lYXBwOm9uZWFwcA=="},
                data={
                    "client_id": "oneapp",
                    "redirect_uri": "com.toyota.oneapp:/oauth2Callback",
                    "grant_type": "refresh_token",
                    "code_verifier": "plain",
                    "refresh_token": self._refresh_token,
                },
            )
            logger.debug(format_httpx_response(resp))

            if resp.status_code != HTTPStatus.OK:
                msg = f"Token refresh failed. {resp.status_code}, {resp.text}."
                raise ToyotaLoginError(msg)

            self._update_tokens(resp.json())

    def _update_tokens(self, response_data: dict[str, Any]) -> None:
        """Update token information from response data.

        Args:
            response_data: Token response data from API

        Raises:
            ToyotaLoginError: If required tokens are missing

        """
        # Verify all required tokens are present
        required_fields = ["access_token", "id_token", "refresh_token", "expires_in"]
        if missing_fields := [
            field for field in required_fields if field not in response_data
        ]:
            msg = f"Token retrieval failed. Missing fields: {', '.join(missing_fields)}"
            raise ToyotaLoginError(msg)

        # Decode the JWT to get the UUID. EU id_tokens carry a "uuid" claim;
        # AU (tmca) id_tokens instead expose the same account GUID as "sub".
        decoded_id_token = jwt.decode(
            response_data["id_token"],
            algorithms=["RS256"],
            options={"verify_signature": False},
            audience="oneappsdkclient",
        )
        uuid = decoded_id_token.get("uuid") or decoded_id_token.get("sub")
        if not uuid:
            msg = "Token retrieval failed. No 'uuid' or 'sub' claim in id_token."
            raise ToyotaLoginError(msg)

        # Calculate expiration time
        expiration = datetime.now(timezone.utc) + timedelta(
            seconds=response_data["expires_in"]
        )

        # Update token info
        self._token_info = TokenInfo(
            access_token=response_data["access_token"],
            refresh_token=response_data["refresh_token"],
            uuid=uuid,
            expiration=expiration,
        )

        # Update cache
        self._TOKEN_CACHE[self._username] = self._token_info

    async def request_raw(  # noqa: PLR0913
        self,
        method: str,
        endpoint: str,
        vin: str | None = None,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> httpx.Response:
        """Send a raw HTTP request to the Toyota API.

        Args:
            method: The HTTP method to use ("GET", "POST", "PUT", "DELETE")
            endpoint: The API endpoint to request
            brand: Brand of the car (T for Toyota, L for Lexus)
            vin: Vehicle Identification Number (optional)
            body: Request body as dictionary (optional)
            params: URL query parameters (optional)
            headers: Additional HTTP headers (optional)

        Returns:
            The raw HTTP response

        Raises:
            ToyotaInternalError: If an invalid HTTP method is provided
            ToyotaApiError: If the API returns an error response

        """
        valid_methods = ("GET", "POST", "PUT", "DELETE")
        if method not in valid_methods:
            msg = f"Invalid request method: {method}. Must be one of {valid_methods}"
            raise ToyotaInternalError(msg)

        # Ensure we have a valid token
        if not self._is_token_valid():
            await self._update_token()

        # Prepare headers
        request_headers = self._prepare_headers(vin, headers)

        # Make the request using the reused client (TCP/TLS state is pooled
        # across calls instead of a fresh SSL handshake per request). Retry on
        # 429 (rate-limited) and 5xx with exponential backoff; 4xx client
        # errors fail fast. Total worst-case wait when Toyota is unhealthy:
        # 2 + 4 + 8 = 14s.
        if self._client is None:
            ssl_ctx = await self._get_ssl_context()
            self._client = httpx.AsyncClient(timeout=self._timeout, verify=ssl_ctx)

        backoffs_s = (2, 4, 8)
        response: httpx.Response | None = None

        for attempt in range(len(backoffs_s) + 1):
            response = await self._client.request(
                method,
                f"{self._api_base_url}{endpoint}",
                headers=request_headers,
                json=body,
                params=params,
                follow_redirects=True,
            )
            logger.debug(format_httpx_response(response))

            if response.status_code in [HTTPStatus.OK, HTTPStatus.ACCEPTED]:
                return response

            is_transient = (
                response.status_code == HTTPStatus.TOO_MANY_REQUESTS
                or response.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR
            )
            if not is_transient or attempt >= len(backoffs_s):
                break

            wait = backoffs_s[attempt]
            logger.warning(
                "Toyota API {} on {}; retrying in {}s (attempt {} of {})",
                response.status_code,
                endpoint,
                wait,
                attempt + 2,
                len(backoffs_s) + 1,
            )
            await asyncio.sleep(wait)

        msg = f"Request Failed. {response.status_code}, {response.text}."
        raise ToyotaApiError(msg)

    async def aclose(self) -> None:
        """Release the pooled httpx client. Safe to call multiple times."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _prepare_headers(
        self,
        vin: str | None = None,
        additional_headers: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """Prepare headers for API requests.

        Args:
            vin: Vehicle Identification Number (optional)
            additional_headers: Additional headers to include (optional)

        Returns:
            Complete headers dictionary

        """
        brand = self._brand
        headers = {
            "x-api-key": self._api_key,
            "API_KEY": self._api_key,
            "x-guid": self._uuid,
            "guid": self._uuid,
            "x-client-ref": generate_hmac_sha256(CLIENT_VERSION, self._uuid),
            "x-correlationid": str(uuid4()),
            "x-appversion": CLIENT_VERSION,
            "x-channel": "ONEAPP",
            "x-brand": brand,
            "x-region": self._region,
            "authorization": f"Bearer {self._token}",
            "user-agent": "okhttp/4.10.0",
        }

        if brand == "L":
            headers["x-appbrand"] = "L"
            headers["brand"] = "L"

        # Add VIN if provided
        if vin is not None:
            headers["vin"] = vin

        # Add additional headers
        if additional_headers:
            headers |= additional_headers

        return headers

    async def request_json(  # noqa: PLR0913
        self,
        method: str,
        endpoint: str,
        vin: str | None = None,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a request to the Toyota API and return JSON response.

        Args:
            method: The HTTP method to use ("GET", "POST", "PUT", "DELETE")
            endpoint: The API endpoint to request
            vin: Vehicle Identification Number (optional)
            body: Request body as dictionary (optional)
            params: URL query parameters (optional)
            headers: Additional HTTP headers (optional)

        Returns:
            The JSON response as a dictionary

        Examples:
            response = await controller.request_json("GET", "/cars", vin="1234567890")

        """
        response = await self.request_raw(method, endpoint, vin, body, params, headers)
        return response.json() if response.content else {}
