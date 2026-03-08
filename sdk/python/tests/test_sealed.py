"""Unit tests for sealed mode in the Phoenix Python SDK."""

import base64
import json
import os
import tempfile
import time
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

try:
    import nacl.public
    import nacl.utils
    _HAS_NACL = True
except ImportError:
    _HAS_NACL = False

from phoenix_secrets.client import PhoenixClient, PhoenixError


def _generate_keypair():
    """Generate an X25519 keypair for testing."""
    priv = nacl.public.PrivateKey.generate()
    return priv, priv.public_key


def _seal_value(path, ref, value, recipient_pub):
    """Create a sealed envelope for testing."""
    eph = nacl.public.PrivateKey.generate()
    box = nacl.public.Box(eph, recipient_pub)
    nonce = nacl.utils.random(24)

    payload = json.dumps({
        "path": path,
        "ref": ref,
        "value": value,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }).encode()

    ciphertext = box.encrypt(payload, nonce).ciphertext

    return {
        "version": 1,
        "algorithm": "x25519-xsalsa20-poly1305",
        "path": path,
        "ref": ref,
        "ephemeral_key": base64.b64encode(eph.public_key.encode()).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def _write_key_file(priv_key):
    """Write a private key to a temp file and return the path."""
    fd, path = tempfile.mkstemp(suffix=".seal.key")
    os.write(fd, base64.b64encode(priv_key.encode()))
    os.close(fd)
    os.chmod(path, 0o600)
    return path


class MockSealedServer(BaseHTTPRequestHandler):
    """Mock Phoenix server that returns sealed responses."""

    pub_key = None  # Set by test

    def do_POST(self):
        if self.path == "/v1/resolve":
            content_len = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_len))
            refs = body.get("refs", [])

            seal_key_header = self.headers.get("X-Phoenix-Seal-Key", "")
            if seal_key_header and self.pub_key:
                pub_bytes = base64.b64decode(seal_key_header)
                pub = nacl.public.PublicKey(pub_bytes)
                sealed_values = {}
                for ref in refs:
                    # Extract path from ref (phoenix://path)
                    path = ref.replace("phoenix://", "")
                    sealed_values[ref] = _seal_value(path, ref, f"secret-for-{path}", pub)
                resp = json.dumps({"sealed_values": sealed_values}).encode()
            else:
                values = {ref: f"plain-{ref}" for ref in refs}
                resp = json.dumps({"values": values}).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress output


@unittest.skipUnless(_HAS_NACL, "PyNaCl not installed (pip install phoenix-secrets[sealed])")
class TestSealedMode(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv, cls.pub = _generate_keypair()
        MockSealedServer.pub_key = cls.pub
        cls.server = HTTPServer(("127.0.0.1", 0), MockSealedServer)
        cls.port = cls.server.server_address[1]
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_sealed_resolve(self):
        key_path = _write_key_file(self.priv)
        try:
            client = PhoenixClient(
                server=f"http://127.0.0.1:{self.port}",
                token="test",
                seal_key_path=key_path,
            )
            val = client.resolve("phoenix://ns/secret")
            self.assertEqual(val, "secret-for-ns/secret")
        finally:
            os.unlink(key_path)

    def test_sealed_batch_resolve(self):
        key_path = _write_key_file(self.priv)
        try:
            client = PhoenixClient(
                server=f"http://127.0.0.1:{self.port}",
                token="test",
                seal_key_path=key_path,
            )
            result = client.resolve_batch([
                "phoenix://ns/k1",
                "phoenix://ns/k2",
            ])
            self.assertEqual(result["values"]["phoenix://ns/k1"], "secret-for-ns/k1")
            self.assertEqual(result["values"]["phoenix://ns/k2"], "secret-for-ns/k2")
        finally:
            os.unlink(key_path)

    def test_plaintext_without_seal_key(self):
        client = PhoenixClient(
            server=f"http://127.0.0.1:{self.port}",
            token="test",
        )
        val = client.resolve("phoenix://ns/secret")
        self.assertEqual(val, "plain-phoenix://ns/secret")

    def test_unseal_bad_version(self):
        key_path = _write_key_file(self.priv)
        try:
            client = PhoenixClient(
                server=f"http://127.0.0.1:{self.port}",
                token="test",
                seal_key_path=key_path,
            )
            env = {"version": 99, "algorithm": "x25519-xsalsa20-poly1305"}
            with self.assertRaises(PhoenixError) as ctx:
                client._unseal_envelope(env)
            self.assertIn("version", str(ctx.exception))
        finally:
            os.unlink(key_path)

    def test_unseal_bad_algorithm(self):
        key_path = _write_key_file(self.priv)
        try:
            client = PhoenixClient(
                server=f"http://127.0.0.1:{self.port}",
                token="test",
                seal_key_path=key_path,
            )
            env = {"version": 1, "algorithm": "aes-gcm"}
            with self.assertRaises(PhoenixError) as ctx:
                client._unseal_envelope(env)
            self.assertIn("algorithm", str(ctx.exception))
        finally:
            os.unlink(key_path)

    def test_set_seal_key_bad_file(self):
        with self.assertRaises(Exception):
            client = PhoenixClient(
                server="http://localhost:9999",
                token="test",
                seal_key_path="/nonexistent/path",
            )

    def test_set_seal_key_bad_content(self):
        fd, path = tempfile.mkstemp()
        os.write(fd, b"not-valid-base64!!!")
        os.close(fd)
        try:
            with self.assertRaises(PhoenixError):
                client = PhoenixClient(
                    server="http://localhost:9999",
                    token="test",
                    seal_key_path=path,
                )
        finally:
            os.unlink(path)


    def test_ref_swap_attack_rejected(self):
        """Server swaps map keys — client must reject."""
        key_path = _write_key_file(self.priv)
        try:
            client = PhoenixClient(
                server=f"http://127.0.0.1:{self.port}",
                token="test",
                seal_key_path=key_path,
            )
            # Monkey-patch the mock to return swapped envelopes
            original_do_POST = MockSealedServer.do_POST

            def swapped_handler(handler_self):
                if handler_self.path == "/v1/resolve":
                    content_len = int(handler_self.headers.get("Content-Length", 0))
                    body = json.loads(handler_self.rfile.read(content_len))
                    seal_key_header = handler_self.headers.get("X-Phoenix-Seal-Key", "")
                    pub_bytes = base64.b64decode(seal_key_header)
                    pub = nacl.public.PublicKey(pub_bytes)
                    # Create envelopes with correct refs but swap map keys
                    env_a = _seal_value("ns/a", "phoenix://ns/a", "A", pub)
                    env_b = _seal_value("ns/b", "phoenix://ns/b", "B", pub)
                    resp = json.dumps({
                        "sealed_values": {
                            "phoenix://ns/a": env_b,  # swapped!
                            "phoenix://ns/b": env_a,  # swapped!
                        }
                    }).encode()
                    handler_self.send_response(200)
                    handler_self.send_header("Content-Type", "application/json")
                    handler_self.end_headers()
                    handler_self.wfile.write(resp)

            MockSealedServer.do_POST = swapped_handler
            try:
                with self.assertRaises(PhoenixError) as ctx:
                    client.resolve_batch([
                        "phoenix://ns/a",
                        "phoenix://ns/b",
                    ])
                self.assertIn("mismatch", str(ctx.exception))
            finally:
                MockSealedServer.do_POST = original_do_POST
        finally:
            os.unlink(key_path)


if __name__ == "__main__":
    unittest.main()
