"""Thin HTTP client for the Phoenix secrets management API.

Supports resolve, batch resolve, and health check. No admin operations.
Under 200 lines — if this grows beyond that, it's doing too much.
"""

from __future__ import annotations

import json
import os
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class PhoenixError(Exception):
    """Raised when a Phoenix API call fails."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class PhoenixClient:
    """Client for the Phoenix secrets management HTTP API.

    Args:
        server: Phoenix server URL. Defaults to PHOENIX_SERVER env var
                or http://127.0.0.1:9090.
        token: Bearer token for authentication. Defaults to PHOENIX_TOKEN
               env var.
        timeout: Request timeout in seconds. Defaults to 10.

    Example::

        client = PhoenixClient()
        value = client.resolve("phoenix://myapp/api-key")
    """

    def __init__(
        self,
        server: Optional[str] = None,
        token: Optional[str] = None,
        timeout: int = 10,
    ):
        self.server = (
            server or os.environ.get("PHOENIX_SERVER") or "http://127.0.0.1:9090"
        )
        self.server = self.server.rstrip("/")
        self.token = token or os.environ.get("PHOENIX_TOKEN", "")
        self.timeout = timeout

    def _request(
        self, method: str, path: str, body: Optional[dict] = None
    ) -> dict:
        """Make an authenticated HTTP request to the Phoenix API."""
        url = f"{self.server}{path}"
        data = json.dumps(body).encode() if body else None

        req = Request(url, data=data, method=method)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if data:
            req.add_header("Content-Type", "application/json")

        try:
            with urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            try:
                err_body = json.loads(e.read())
                msg = err_body.get("error", f"HTTP {e.code}")
            except (json.JSONDecodeError, AttributeError):
                msg = f"HTTP {e.code}"
            raise PhoenixError(msg, status=e.code) from None
        except URLError as e:
            raise PhoenixError(f"server unreachable: {e.reason}") from None

    def health(self) -> dict:
        """Check server health.

        Returns:
            Dict with at least ``{"status": "ok"}`` on success.

        Raises:
            PhoenixError: If the server is unreachable or unhealthy.
        """
        return self._request("GET", "/v1/health")

    def resolve(self, ref: str) -> str:
        """Resolve a single ``phoenix://`` reference to its secret value.

        Args:
            ref: A phoenix:// reference (e.g. ``phoenix://myapp/api-key``).

        Returns:
            The plaintext secret value.

        Raises:
            PhoenixError: If the reference cannot be resolved (not found,
                          access denied, attestation failure, etc.).
        """
        result = self.resolve_batch([ref])
        if ref in result.get("errors", {}):
            raise PhoenixError(result["errors"][ref])
        return result["values"][ref]

    def resolve_batch(self, refs: list[str]) -> dict:
        """Resolve multiple ``phoenix://`` references in one API call.

        Args:
            refs: List of phoenix:// references.

        Returns:
            Dict with ``values`` (ref → secret) and optionally ``errors``
            (ref → error message) keys.

        Raises:
            PhoenixError: If the API call itself fails (auth, network, etc.).
        """
        if not refs:
            raise PhoenixError("refs must not be empty")
        return self._request("POST", "/v1/resolve", {"refs": refs})

    def verify(self, refs: list[str]) -> dict:
        """Dry-run resolve — check that references are valid and accessible
        without returning plaintext secret values.

        Args:
            refs: List of phoenix:// references.

        Returns:
            Dict with ``values`` (ref → ``"ok"``) and optionally ``errors``
            (ref → error message) keys.

        Raises:
            PhoenixError: If the API call itself fails.
        """
        if not refs:
            raise PhoenixError("refs must not be empty")
        return self._request("POST", "/v1/resolve?dry_run=true", {"refs": refs})

    def status(self) -> dict:
        """Get comprehensive server status (requires admin token).

        Returns:
            Dict with server status, secret count, agent count, policy
            summary, and recent audit entries.

        Raises:
            PhoenixError: If unauthorized or the server is unreachable.
        """
        return self._request("GET", "/v1/status")
