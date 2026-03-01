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
