"""Integration tests for the Phoenix Python SDK.

These tests require a running Phoenix server. Set PHOENIX_SERVER and
PHOENIX_TOKEN environment variables, or skip with:

    pytest -m "not integration"

To run against a local dev server:

    phoenix-server --init /tmp/phoenix-test && phoenix-server --data /tmp/phoenix-test &
    PHOENIX_SERVER=http://127.0.0.1:9090 PHOENIX_TOKEN=admin-token pytest
"""

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
