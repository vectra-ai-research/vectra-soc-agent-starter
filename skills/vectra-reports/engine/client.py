"""Vectra REST + Investigation Query client (standalone, parallel-safe).

Differences vs the MCP server's client:

- Loads credentials from the repo-root .env (python-dotenv) rather than the
  MCP config object.
- Uses a true token-bucket rate limiter shared across submit and poll calls,
  which lets multiple in-flight investigation queries run concurrently.
- No MCP/server dependencies — usable as a plain Python library.
"""

from __future__ import annotations

import asyncio
import base64
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)


class VectraAPIError(Exception):
    """Raised for any non-success API response."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_data: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class RateLimitError(VectraAPIError):
    """Raised on HTTP 429 — retryable via tenacity."""

    def __init__(self, retry_after: float | None = None) -> None:
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded (retry_after={retry_after}s)",
            status_code=429,
        )


@dataclass(frozen=True)
class VectraCredentials:
    """OAuth2 client-credentials for a Vectra tenant."""

    base_url: str
    client_id: str
    client_secret: str
    oauth_token_url: str
    rate_limit_requests: int = 5
    rate_limit_period_sec: int = 60

    @property
    def data_api_base(self) -> str:
        """Vectra Data API base — derived from the tenant hostname.

        The REST API base is typically ``https://<tenant>/api/v3.4``;
        the Data API (investigations) lives at ``https://<tenant>/api/v3.4``
        on the same host, so we re-use the hostname.
        """
        parsed = urlparse(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}/api/v3.4"


def _find_repo_root() -> Path:
    """Find the repo root that owns the centralized .env file."""
    starts = [Path.cwd(), Path(__file__).resolve()]
    for start in starts:
        base = start if start.is_dir() else start.parent
        for path in (base, *base.parents):
            if (path / "AGENTS.md").is_file():
                return path
    return Path(__file__).resolve().parents[3]


def _find_env_file() -> Path | None:
    """Return the centralized repo-root .env file, if present."""
    path = _find_repo_root() / ".env"
    if path.is_file():
        return path
    return None


def load_credentials() -> VectraCredentials:
    """Load credentials from environment, bootstrapped from repo-root .env.

    Existing environment variables always win; otherwise only the repo-root
    ``.env`` is loaded. Skill-local env files and user-home credential files are
    intentionally ignored so credentials stay centralized.
    """
    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]
    except ImportError:
        load_dotenv = None  # graceful — env may already be set
    if load_dotenv is not None:
        env_file = _find_env_file()
        if env_file is not None:
            load_dotenv(env_file, override=False)

    base_url = os.environ.get("VECTRA_BASE_URL", "").rstrip("/")
    client_id = os.environ.get("VECTRA_CLIENT_ID", "")
    client_secret = os.environ.get("VECTRA_CLIENT_SECRET", "")
    if not (base_url and client_id and client_secret):
        raise RuntimeError(
            "Missing Vectra credentials. Set VECTRA_BASE_URL, VECTRA_CLIENT_ID, and "
            "VECTRA_CLIENT_SECRET in your environment or in the repo-root .env file."
        )

    parsed = urlparse(base_url)
    default_token_url = f"{parsed.scheme}://{parsed.netloc}/oauth2/token"
    token_url = os.environ.get("VECTRA_OAUTH_TOKEN_URL") or default_token_url

    rate_req = int(os.environ.get("VECTRA_RATE_LIMIT_REQUESTS", "5"))
    rate_period = int(os.environ.get("VECTRA_RATE_LIMIT_PERIOD_SEC", "60"))

    return VectraCredentials(
        base_url=base_url,
        client_id=client_id,
        client_secret=client_secret,
        oauth_token_url=token_url,
        rate_limit_requests=rate_req,
        rate_limit_period_sec=rate_period,
    )


class _TokenBucket:
    """Async token-bucket allowing controlled parallelism.

    A request consumes one token; tokens regenerate at ``capacity / period``
    per second. Allows brief bursts up to ``capacity`` and smooths back to the
    documented limit (5 req / 60s for the Investigation Query endpoint).
    """

    def __init__(self, capacity: int, period_sec: float) -> None:
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._refill_per_sec = capacity / max(period_sec, 0.001)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._tokens = min(
                    self._capacity, self._tokens + elapsed * self._refill_per_sec
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._refill_per_sec
                await asyncio.sleep(wait)


class _TokenManager:
    """OAuth2 client-credentials token manager (cached, refresh-on-expiry)."""

    def __init__(self, creds: VectraCredentials) -> None:
        self._creds = creds
        self._access_token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def get(self) -> str:
        async with self._lock:
            if self._access_token and time.time() < self._expires_at - 60:
                return self._access_token
            await self._refresh()
            return self._access_token  # type: ignore[return-value]

    async def _refresh(self) -> None:
        auth = base64.b64encode(
            f"{self._creds.client_id}:{self._creds.client_secret}".encode()
        ).decode()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                self._creds.oauth_token_url,
                data={"grant_type": "client_credentials"},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {auth}",
                },
            )
        if resp.status_code == 401:
            raise VectraAPIError("Invalid OAuth2 credentials", status_code=401)
        if not resp.is_success:
            raise VectraAPIError(
                f"Token refresh failed: HTTP {resp.status_code}",
                status_code=resp.status_code,
                response_data=resp.text,
            )
        body = resp.json()
        self._access_token = body["access_token"]
        self._expires_at = time.time() + int(body.get("expires_in", 3600))


class VectraClient:
    """Async client covering REST + Investigation Query endpoints.

    Use as an async context manager:

    ```python
    creds = load_credentials()
    async with VectraClient(creds) as client:
        job = await client.submit_investigation_query("SELECT 1")
    ```
    """

    def __init__(self, credentials: VectraCredentials) -> None:
        self.credentials = credentials
        self._tokens = _TokenManager(credentials)
        self._bucket = _TokenBucket(
            capacity=credentials.rate_limit_requests,
            period_sec=credentials.rate_limit_period_sec,
        )
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def __aenter__(self) -> VectraClient:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    async def _headers(self) -> dict[str, str]:
        token = await self._tokens.get()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "vectra-reports-skill/0.1.0",
        }

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=60),
        retry=retry_if_exception_type(
            (httpx.ConnectError, httpx.TimeoutException, RateLimitError)
        ),
    )
    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        absolute_url: str | None = None,
    ) -> dict[str, Any]:
        await self._bucket.acquire()
        url = absolute_url or urljoin(
            self.credentials.base_url + "/", endpoint.lstrip("/")
        )
        resp = await self._http.request(
            method,
            url,
            params=params,
            json=json_data,
            headers=await self._headers(),
        )
        if resp.status_code == 401:
            raise VectraAPIError("Authentication failed", status_code=401)
        if resp.status_code == 403:
            raise VectraAPIError("Authorization denied", status_code=403)
        if resp.status_code == 404:
            raise VectraAPIError("Resource not found", status_code=404)
        if resp.status_code == 429:
            # No inline sleep here — tenacity owns the retry wait. Sleeping on
            # Retry-After *and* raising would double the back-off.
            retry_after = resp.headers.get("Retry-After")
            wait_sec = float(retry_after) if retry_after else None
            raise RateLimitError(retry_after=wait_sec)
        if not resp.is_success:
            try:
                payload = resp.json()
            except ValueError:
                payload = resp.text
            raise VectraAPIError(
                f"API request failed: HTTP {resp.status_code}",
                status_code=resp.status_code,
                response_data=payload,
            )
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return {"data": resp.text}

    # ── Investigation Query API ───────────────────────────────────────────────

    async def submit_investigation_query(
        self, query: str, version: str = "1.0"
    ) -> dict[str, Any]:
        """Submit an async SQL job and return the response containing ``request_id``."""
        url = f"{self.credentials.data_api_base}/investigations"
        body = await self._request(
            "POST", "", json_data={"query": query, "version": version}, absolute_url=url
        )
        # API may use either snake_case or camelCase — normalise.
        rid = body.get("request_id") or body.get("requestId")
        if not rid:
            raise VectraAPIError(
                f"No request_id in submission response: {body}", status_code=None
            )
        body["request_id"] = rid
        return body

    async def get_investigation_results(
        self, request_id: str, page: int = 1, page_size: int = 500
    ) -> dict[str, Any]:
        """Fetch one page of completed query results."""
        url = f"{self.credentials.data_api_base}/investigations/{request_id}"
        body = await self._request(
            "GET",
            "",
            params={"page": page, "page_size": page_size},
            absolute_url=url,
        )
        body["request_id"] = request_id
        return body

    # ── Generic REST helpers ──────────────────────────────────────────────────

    async def get_detections(self, **params: Any) -> dict[str, Any]:
        clean = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "detections", params=clean)

    async def get_hosts(self, **params: Any) -> dict[str, Any]:
        clean = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "hosts", params=clean)

    async def get_accounts(self, **params: Any) -> dict[str, Any]:
        clean = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "accounts", params=clean)

    async def get_entities(self, **params: Any) -> dict[str, Any]:
        clean = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "entities", params=clean)

    async def get_assignments(self, **params: Any) -> dict[str, Any]:
        clean = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "assignments", params=clean)

    async def get_health(self) -> dict[str, Any]:
        return await self._request("GET", "health")
