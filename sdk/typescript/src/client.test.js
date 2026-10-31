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
    const orig = process.env.PHOENIX_SERVER;
    delete process.env.PHOENIX_SERVER;
    try {
      const c = new PhoenixClient();
      assert.equal(c.server, "http://127.0.0.1:9090");
    } finally {
      if (orig !== undefined) {
        process.env.PHOENIX_SERVER = orig;
      }
    }
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

describe("structured denials", () => {
  it("shows code and detail", async () => {
    const { url, close } = await createTestServer((req, res) => {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "access_denied", code: "ACL_DENIED", detail: "read_value is not allowed", next_step: "ask_user" }));
    });
    try {
      const c = new PhoenixClient({ server: url, token: "tok" });
      await assert.rejects(c.health(), (err) => {
        assert.ok(err instanceof PhoenixError);
        assert.equal(err.status, 403);
        assert.equal(err.message, "[ACL_DENIED] read_value is not allowed");
        return true;
      });
    } finally {
      close();
    }
  });

  async function denialError(status, body, call) {
    const { url, close } = await createTestServer((req, res) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    });
    try {
      const c = new PhoenixClient({ server: url, token: "tok" });
      let caught;
      await assert.rejects(call(c), (err) => {
        assert.ok(err instanceof PhoenixError);
        caught = err;
        return true;
      });
      return caught;
    } finally {
      close();
    }
  }
  const health = (c) => c.health();
  const resolve = (c) => c.resolve("phoenix://a/b");

  it("resolve error includes the per-ref code", async () => {
    const err = await denialError(200, {
      values: {},
      errors: { "phoenix://a/b": "attestation required" },
      error_codes: { "phoenix://a/b": { code: "SEALED_REQUIRED", next_step: "use_exec" } },
    }, resolve);
    assert.equal(err.message, "[SEALED_REQUIRED] attestation required");
  });

  it("resolve error without error_codes is unchanged", async () => {
    const err = await denialError(200, { values: {}, errors: { "phoenix://a/b": "secret not found" } }, resolve);
    assert.equal(err.message, "secret not found");
  });

  it("sanitizes server text", async () => {
    const hostile = "a\x1b[2Jb\x1b]52;c;Zm9v\x07c\u202ed\u200be\nf";
    const errs = [
      await denialError(403, { error: "access_denied", code: "ACL_DENIED", detail: hostile }, health),
      await denialError(403, { error: hostile }, health),
      await denialError(200, {
        values: {},
        errors: { "phoenix://a/b": hostile },
        error_codes: { "phoenix://a/b": { code: "ACL_DENIED" } },
      }, resolve),
    ];
    for (const err of errs) {
      for (const bad of ["\x1b", "\x07", "\u202e", "\u200b", "\n"]) {
        assert.ok(!err.message.includes(bad), `kept ${JSON.stringify(bad)}: ${JSON.stringify(err.message)}`);
      }
      assert.ok(err.message.includes("a[2Jb]52;c;Zm9vcdef"), err.message);
    }
    const long = await denialError(403, { code: "ACL_DENIED", detail: "x".repeat(1000) }, health);
    assert.equal(long.message, "[ACL_DENIED] " + "x".repeat(300) + "...");
  });

  it("drops malformed codes", async () => {
    for (const code of ["acl_denied", "ACL DENIED", "ACL_DENIED\n", "<b>X</b>", "A".repeat(65)]) {
      const err = await denialError(403, { code, detail: "denied" }, health);
      assert.equal(err.message, "denied", code);
      const res = await denialError(200, {
        values: {},
        errors: { "phoenix://a/b": "denied" },
        error_codes: { "phoenix://a/b": { code } },
      }, resolve);
      assert.equal(res.message, "denied", code);
    }
  });
});
