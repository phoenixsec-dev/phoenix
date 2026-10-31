"""Integration tests for the Phoenix Python SDK.

These tests require a running Phoenix server. Set PHOENIX_SERVER and
PHOENIX_TOKEN environment variables, or skip with:

    pytest -m "not integration"

To run against a local dev server:

    phoenix-server --init /tmp/phoenix-test
    phoenix-server --config /tmp/phoenix-test/config.json &
    PHOENIX_SERVER=http://127.0.0.1:9090 PHOENIX_TOKEN=admin-token python3 -m unittest discover
"""

import json
import os
import unittest

from phoenix_secrets import PhoenixClient
from phoenix_secrets.client import PhoenixError


def _has_server():
    """Check if a Phoenix server is reachable."""
    try:
        client = PhoenixClient()
        client.health()
        return True
    except Exception:
        return False


SKIP_REASON = "No Phoenix server available (set PHOENIX_SERVER + PHOENIX_TOKEN)"


class TestClientUnit(unittest.TestCase):
    """Unit tests that don't need a server."""

    def test_init_defaults(self):
        client = PhoenixClient()
        self.assertEqual(client.server, os.environ.get("PHOENIX_SERVER", "http://127.0.0.1:9090"))
        self.assertEqual(client.timeout, 10)

    def test_init_custom(self):
        client = PhoenixClient(server="https://phoenix.example.com", token="my-token", timeout=30)
        self.assertEqual(client.server, "https://phoenix.example.com")
        self.assertEqual(client.token, "my-token")
        self.assertEqual(client.timeout, 30)

    def test_init_strips_trailing_slash(self):
        client = PhoenixClient(server="http://localhost:9090/")
        self.assertEqual(client.server, "http://localhost:9090")

    def test_resolve_batch_empty_refs(self):
        client = PhoenixClient()
        with self.assertRaises(PhoenixError) as ctx:
            client.resolve_batch([])
        self.assertIn("empty", str(ctx.exception))

    def test_verify_empty_refs(self):
        client = PhoenixClient()
        with self.assertRaises(PhoenixError) as ctx:
            client.verify([])
        self.assertIn("empty", str(ctx.exception))

    def test_unreachable_server_raises_phoenix_error(self):
        # Port 1 is almost certainly not running a Phoenix server
        client = PhoenixClient(server="http://127.0.0.1:1", timeout=1)
        with self.assertRaises(PhoenixError) as ctx:
            client.health()
        self.assertIn("unreachable", str(ctx.exception))
        self.assertEqual(ctx.exception.status, 0)

    def test_structured_denial_shows_code_and_detail(self):
        import io
        from unittest import mock
        from urllib.error import HTTPError

        body = b'{"error":"access_denied","code":"ACL_DENIED","detail":"read_value is not allowed","next_step":"ask_user"}'
        err = HTTPError("http://x/v1/health", 403, "Forbidden", {}, io.BytesIO(body))
        with mock.patch("phoenix_secrets.client.urlopen", side_effect=err):
            with self.assertRaises(PhoenixError) as ctx:
                PhoenixClient(server="http://x").health()
        self.assertEqual(str(ctx.exception), "[ACL_DENIED] read_value is not allowed")
        self.assertEqual(ctx.exception.status, 403)

    def _denial_error(self, body: dict) -> PhoenixError:
        import io
        from unittest import mock
        from urllib.error import HTTPError

        err = HTTPError("http://x/v1/health", 403, "Forbidden", {}, io.BytesIO(json.dumps(body).encode()))
        with mock.patch("phoenix_secrets.client.urlopen", side_effect=err):
            with self.assertRaises(PhoenixError) as ctx:
                PhoenixClient(server="http://x").health()
        return ctx.exception

    def _resolve_error(self, response: dict) -> PhoenixError:
        from unittest import mock

        client = PhoenixClient(server="http://x")
        with mock.patch.object(client, "_request", return_value=response):
            with self.assertRaises(PhoenixError) as ctx:
                client.resolve("phoenix://a/b")
        return ctx.exception

    def test_resolve_error_includes_per_ref_code(self):
        err = self._resolve_error({
            "values": {},
            "errors": {"phoenix://a/b": "attestation required"},
            "error_codes": {"phoenix://a/b": {"code": "SEALED_REQUIRED", "next_step": "use_exec"}},
        })
        self.assertEqual(str(err), "[SEALED_REQUIRED] attestation required")

    def test_resolve_error_without_error_codes_unchanged(self):
        err = self._resolve_error({"values": {}, "errors": {"phoenix://a/b": "secret not found"}})
        self.assertEqual(str(err), "secret not found")

    def test_server_text_is_sanitized(self):
        hostile = "a\x1b[2Jb\x1b]52;c;Zm9v\x07c\u202ed\u200be\nf"
        cases = [
            self._denial_error({"error": "access_denied", "code": "ACL_DENIED", "detail": hostile}),
            self._denial_error({"error": hostile}),
            self._resolve_error({
                "values": {},
                "errors": {"phoenix://a/b": hostile},
                "error_codes": {"phoenix://a/b": {"code": "ACL_DENIED"}},
            }),
        ]
        for err in cases:
            msg = str(err)
            for bad in ("\x1b", "\x07", "\u202e", "\u200b", "\n"):
                self.assertNotIn(bad, msg)
            self.assertIn("a[2Jb]52;c;Zm9vcdef", msg)

        long_err = self._denial_error({"code": "ACL_DENIED", "detail": "x" * 1000})
        self.assertEqual(str(long_err), "[ACL_DENIED] " + "x" * 300 + "...")

    def test_malformed_code_is_dropped(self):
        for code in ("acl_denied", "ACL DENIED", "ACL_DENIED\n", "<b>X</b>", "A" * 65):
            err = self._denial_error({"code": code, "detail": "denied"})
            self.assertEqual(str(err), "denied", code)
            res = self._resolve_error({
                "values": {},
                "errors": {"phoenix://a/b": "denied"},
                "error_codes": {"phoenix://a/b": {"code": code}},
            })
            self.assertEqual(str(res), "denied", code)

    def test_phoenix_error_has_status(self):
        err = PhoenixError("not found", status=404)
        self.assertEqual(err.status, 404)
        self.assertEqual(str(err), "not found")


@unittest.skipUnless(_has_server(), SKIP_REASON)
class TestClientIntegration(unittest.TestCase):
    """Integration tests against a live Phoenix server."""

    def setUp(self):
        self.client = PhoenixClient()

    def test_health(self):
        result = self.client.health()
        self.assertEqual(result["status"], "ok")

    def test_resolve_not_found(self):
        with self.assertRaises(PhoenixError) as ctx:
            self.client.resolve("phoenix://nonexistent/key")
        self.assertIn("not found", str(ctx.exception).lower())

    def test_resolve_batch_partial(self):
        result = self.client.resolve_batch([
            "phoenix://nonexistent/key1",
            "phoenix://nonexistent/key2",
        ])
        self.assertIn("errors", result)

    def test_verify_dry_run(self):
        result = self.client.verify(["phoenix://nonexistent/key"])
        self.assertIn("errors", result)
        self.assertIn("not found", result["errors"]["phoenix://nonexistent/key"].lower())


if __name__ == "__main__":
    unittest.main()
