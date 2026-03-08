"""Thin HTTP client for the Phoenix secrets management API.

Supports resolve, batch resolve, and health check. No admin operations.
Sealed mode auto-decrypts when PyNaCl is installed and a seal key is configured.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import nacl.public
    import nacl.utils

    _HAS_NACL = True
except ImportError:
    _HAS_NACL = False


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
        seal_key_path: Optional[str] = None,
    ):
        self.server = (
            server or os.environ.get("PHOENIX_SERVER") or "http://127.0.0.1:9090"
        )
        self.server = self.server.rstrip("/")
        self.token = token or os.environ.get("PHOENIX_TOKEN", "")
        self.timeout = timeout
        self._seal_priv: Optional[bytes] = None
        self._seal_pub_b64: Optional[str] = None

        key_path = seal_key_path or os.environ.get("PHOENIX_SEAL_KEY")
        if key_path:
            self.set_seal_key(key_path)

    def set_seal_key(self, path: str) -> None:
        """Load a seal private key, enabling sealed mode.

        Requires ``pip install phoenix-secrets[sealed]`` (PyNaCl).
        """
        if not _HAS_NACL:
            raise PhoenixError(
                "PyNaCl is required for sealed mode: pip install phoenix-secrets[sealed]"
            )
        with open(path) as f:
            raw = f.read().strip()
        try:
            priv_bytes = base64.b64decode(raw)
        except Exception as e:
            raise PhoenixError(f"invalid seal key encoding: {e}") from None
        if len(priv_bytes) != 32:
            raise PhoenixError(f"seal key must be 32 bytes, got {len(priv_bytes)}")
        self._seal_priv = priv_bytes
        priv_key = nacl.public.PrivateKey(priv_bytes)
        self._seal_pub_b64 = base64.b64encode(
            priv_key.public_key.encode()
        ).decode()

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
        if self._seal_pub_b64:
            req.add_header("X-Phoenix-Seal-Key", self._seal_pub_b64)

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

        When sealed mode is enabled, responses are auto-decrypted transparently.

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
        result = self._request("POST", "/v1/resolve", {"refs": refs})

        if self._seal_priv and "sealed_values" in result:
            values = {}
            for ref, env in result["sealed_values"].items():
                if env.get("ref") != ref:
                    raise PhoenixError(
                        f"sealed envelope ref mismatch: map key {ref!r}, envelope {env.get('ref')!r}"
                    )
                values[ref] = self._unseal_envelope(env)
            result["values"] = values
            del result["sealed_values"]

        return result

    def _unseal_envelope(self, env: dict) -> str:
        """Decrypt a sealed envelope using the loaded private key."""
        if not _HAS_NACL or not self._seal_priv:
            raise PhoenixError("sealed mode not configured")

        if env.get("version") != 1:
            raise PhoenixError(f"unsupported seal version: {env.get('version')}")
        if env.get("algorithm") != "x25519-xsalsa20-poly1305":
            raise PhoenixError(f"unsupported seal algorithm: {env.get('algorithm')}")

        eph_pub = base64.b64decode(env["ephemeral_key"])
        nonce = base64.b64decode(env["nonce"])
        ciphertext = base64.b64decode(env["ciphertext"])

        priv_key = nacl.public.PrivateKey(self._seal_priv)
        eph_pub_key = nacl.public.PublicKey(eph_pub)
        box = nacl.public.Box(priv_key, eph_pub_key)

        plaintext = box.decrypt(ciphertext, nonce)
        payload = json.loads(plaintext)

        if payload.get("path") != env.get("path"):
            raise PhoenixError("path mismatch in sealed envelope")
        if payload.get("ref") != env.get("ref"):
            raise PhoenixError("ref mismatch in sealed envelope")

        return payload["value"]

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
