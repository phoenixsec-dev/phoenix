const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { PhoenixClient, PhoenixError } = require("./client");

function createTestServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      resolve({ url: `http://127.0.0.1:${port}`, close: () => srv.close() });
    });
  });
}

describe("PhoenixClient", () => {
  it("health returns status", async () => {
    const { url, close } = await createTestServer((req, res) => {
      assert.equal(req.url, "/v1/health");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok" }));
    });

    try {
      const c = new PhoenixClient({ server: url, token: "tok" });
      const result = await c.health();
      assert.equal(result.status, "ok");
    } finally {
      close();
    }
  });

  it("resolve returns secret value", async () => {
    const { url, close } = await createTestServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        assert.deepEqual(parsed.refs, ["phoenix://app/key"]);
        assert.equal(req.headers.authorization, "Bearer test-tok");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ values: { "phoenix://app/key": "secret123" } })
        );
      });
    });

    try {
      const c = new PhoenixClient({ server: url, token: "test-tok" });
      const val = await c.resolve("phoenix://app/key");
      assert.equal(val, "secret123");
    } finally {
      close();
    }
  });

  it("resolveBatch returns multiple values", async () => {
    const { url, close } = await createTestServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          values: {
            "phoenix://a/k1": "v1",
            "phoenix://a/k2": "v2",
          },
        })
      );
    });

    try {
      const c = new PhoenixClient({ server: url, token: "tok" });
      const result = await c.resolveBatch([
        "phoenix://a/k1",
        "phoenix://a/k2",
      ]);
      assert.equal(result.values["phoenix://a/k1"], "v1");
      assert.equal(result.values["phoenix://a/k2"], "v2");
    } finally {
      close();
    }
  });

  it("resolve throws on error response", async () => {
    const { url, close } = await createTestServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          values: {},
          errors: { "phoenix://ns/missing": "secret not found" },
        })
      );
    });

    try {
      const c = new PhoenixClient({ server: url, token: "tok" });
      await assert.rejects(() => c.resolve("phoenix://ns/missing"), {
        name: "PhoenixError",
        message: "secret not found",
      });
    } finally {
      close();
    }
  });

  it("throws on HTTP error", async () => {
    const { url, close } = await createTestServer((req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
    });

    try {
      const c = new PhoenixClient({ server: url, token: "bad" });
      await assert.rejects(() => c.health(), (err) => {
        assert.ok(err instanceof PhoenixError);
        assert.equal(err.status, 401);
        assert.equal(err.message, "unauthorized");
        return true;
      });
    } finally {
      close();
    }
  });

  it("throws on empty refs", async () => {
    const c = new PhoenixClient({ server: "http://localhost:1" });
    await assert.rejects(() => c.resolveBatch([]), {
      name: "PhoenixError",
      message: "refs must not be empty",
    });
  });

  it("defaults to standard server URL", () => {
    const c = new PhoenixClient();
    assert.equal(c.server, "http://127.0.0.1:9090");
  });
});

describe("PhoenixClient sealed mode", () => {
  const nacl = require("tweetnacl");
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");

  function generateKeypair() {
    return nacl.box.keyPair();
  }

  function sealValue(secretPath, ref, value, recipientPub) {
    const eph = nacl.box.keyPair();
    const nonce = nacl.randomBytes(24);
    const payload = Buffer.from(
      JSON.stringify({
        path: secretPath,
        ref,
        value,
        issued_at: new Date().toISOString(),
      })
    );
    const ciphertext = nacl.box(payload, nonce, recipientPub, eph.secretKey);
    return {
      version: 1,
      algorithm: "x25519-xsalsa20-poly1305",
      path: secretPath,
      ref,
      ephemeral_key: Buffer.from(eph.publicKey).toString("base64"),
      nonce: Buffer.from(nonce).toString("base64"),
      ciphertext: Buffer.from(ciphertext).toString("base64"),
    };
  }

  function writeKeyFile(privKey) {
    const tmp = path.join(os.tmpdir(), `seal-test-${Date.now()}.key`);
    fs.writeFileSync(tmp, Buffer.from(privKey).toString("base64"), {
      mode: 0o600,
    });
    return tmp;
  }

  it("sealed resolve decrypts transparently", async () => {
    const kp = generateKeypair();
    const keyPath = writeKeyFile(kp.secretKey);

    const { url, close } = await createTestServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        const sealHeader = req.headers["x-phoenix-seal-key"];
        assert.ok(sealHeader, "seal key header should be present");

        const pub = new Uint8Array(Buffer.from(sealHeader, "base64"));
        const ref = parsed.refs[0];
        const secretPath = ref.replace("phoenix://", "");
        const env = sealValue(secretPath, ref, "sealed-secret", pub);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ sealed_values: { [ref]: env } }));
      });
    });

    try {
      const c = new PhoenixClient({ server: url, token: "test" });
      await c.setSealKey(keyPath);
      const val = await c.resolve("phoenix://ns/key");
      assert.equal(val, "sealed-secret");
    } finally {
      close();
      fs.unlinkSync(keyPath);
    }
  });

  it("sealed batch resolve decrypts multiple values", async () => {
    const kp = generateKeypair();
    const keyPath = writeKeyFile(kp.secretKey);

    const { url, close } = await createTestServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        const pub = new Uint8Array(
          Buffer.from(req.headers["x-phoenix-seal-key"], "base64")
        );
        const sealed_values = {};
        for (const ref of parsed.refs) {
          const p = ref.replace("phoenix://", "");
          sealed_values[ref] = sealValue(p, ref, `val-${p}`, pub);
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ sealed_values }));
      });
    });

    try {
      const c = new PhoenixClient({ server: url, token: "test" });
      await c.setSealKey(keyPath);
      const result = await c.resolveBatch([
        "phoenix://ns/k1",
        "phoenix://ns/k2",
      ]);
      assert.equal(result.values["phoenix://ns/k1"], "val-ns/k1");
      assert.equal(result.values["phoenix://ns/k2"], "val-ns/k2");
    } finally {
      close();
      fs.unlinkSync(keyPath);
    }
  });

  it("plaintext resolve works without seal key", async () => {
    const { url, close } = await createTestServer((req, res) => {
      assert.equal(
        req.headers["x-phoenix-seal-key"],
        undefined,
        "no seal header without key"
      );
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ values: { "phoenix://ns/s": "plain" } }));
    });

    try {
      const c = new PhoenixClient({ server: url, token: "test" });
      const val = await c.resolve("phoenix://ns/s");
      assert.equal(val, "plain");
    } finally {
      close();
    }
  });

  it("unseal rejects bad version", async () => {
    const kp = generateKeypair();
    const keyPath = writeKeyFile(kp.secretKey);

    try {
      const c = new PhoenixClient({ server: "http://localhost:1", token: "t" });
      await c.setSealKey(keyPath);
      assert.throws(
        () =>
          c._unsealEnvelope({
            version: 99,
            algorithm: "x25519-xsalsa20-poly1305",
          }),
        { name: "PhoenixError", message: /version/ }
      );
    } finally {
      fs.unlinkSync(keyPath);
    }
  });

  it("unseal rejects bad algorithm", async () => {
    const kp = generateKeypair();
    const keyPath = writeKeyFile(kp.secretKey);

    try {
      const c = new PhoenixClient({ server: "http://localhost:1", token: "t" });
      await c.setSealKey(keyPath);
      assert.throws(
        () => c._unsealEnvelope({ version: 1, algorithm: "aes-gcm" }),
        { name: "PhoenixError", message: /algorithm/ }
      );
    } finally {
      fs.unlinkSync(keyPath);
    }
  });

  it("setSealKey rejects wrong-length key", async () => {
    const tmp = path.join(os.tmpdir(), `seal-bad-${Date.now()}.key`);
    fs.writeFileSync(tmp, Buffer.from("short").toString("base64"), {
      mode: 0o600,
    });

    try {
      const c = new PhoenixClient({ server: "http://localhost:1" });
      await assert.rejects(() => c.setSealKey(tmp), {
        name: "PhoenixError",
        message: /32 bytes/,
      });
    } finally {
      fs.unlinkSync(tmp);
    }
  });

  it("setSealKey rejects missing file", async () => {
    const c = new PhoenixClient({ server: "http://localhost:1" });
    await assert.rejects(() => c.setSealKey("/nonexistent/path"));
  });

  it("rejects ref-swap attack in batch resolve", async () => {
    const kp = generateKeypair();
    const keyPath = writeKeyFile(kp.secretKey);

    const { url, close } = await createTestServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const pub = new Uint8Array(
          Buffer.from(req.headers["x-phoenix-seal-key"], "base64")
        );
        // Create envelopes with correct refs but swap the map keys
        const envA = sealValue("ns/a", "phoenix://ns/a", "A", pub);
        const envB = sealValue("ns/b", "phoenix://ns/b", "B", pub);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            sealed_values: {
              "phoenix://ns/a": envB, // swapped!
              "phoenix://ns/b": envA, // swapped!
            },
          })
        );
      });
    });

    try {
      const c = new PhoenixClient({ server: url, token: "test" });
      await c.setSealKey(keyPath);
      await assert.rejects(
        () =>
          c.resolveBatch(["phoenix://ns/a", "phoenix://ns/b"]),
        { name: "PhoenixError", message: /ref mismatch/ }
      );
    } finally {
      close();
      fs.unlinkSync(keyPath);
    }
  });

  it("bad PHOENIX_SEAL_KEY in constructor does not crash process", async () => {
    const orig = process.env.PHOENIX_SEAL_KEY;
    process.env.PHOENIX_SEAL_KEY = "/no/such/file";
    try {
      const c = new PhoenixClient({ server: "http://localhost:1" });
      // Constructor should not throw — error deferred to first resolve
      await new Promise((r) => setTimeout(r, 20));
      // Attempting resolve should surface the error
      await assert.rejects(() => c.resolve("phoenix://ns/x"));
    } finally {
      if (orig !== undefined) {
        process.env.PHOENIX_SEAL_KEY = orig;
      } else {
        delete process.env.PHOENIX_SEAL_KEY;
      }
    }
  });
});
