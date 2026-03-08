/**
 * Thin HTTP client for the Phoenix secrets management API.
 *
 * Supports health checks, single resolve, and batch resolve.
 * No admin operations. Under 200 lines.
 */

class PhoenixError extends Error {
  /**
   * @param {string} message
   * @param {number} [status=0]
   */
  constructor(message, status = 0) {
    super(message);
    this.name = "PhoenixError";
    this.status = status;
  }
}

class PhoenixClient {
  /**
   * @param {object} [options]
   * @param {string} [options.server] - Phoenix server URL (default: PHOENIX_SERVER env or http://127.0.0.1:9090)
   * @param {string} [options.token] - Bearer token (default: PHOENIX_TOKEN env)
   * @param {number} [options.timeout] - Request timeout in ms (default: 10000)
   * @param {string} [options.sealKeyPath] - Path to seal private key file (enables sealed mode)
   */
  constructor(options = {}) {
    this.server = (
      options.server ||
      (typeof process !== "undefined" && process.env?.PHOENIX_SERVER) ||
      "http://127.0.0.1:9090"
    ).replace(/\/+$/, "");

    this.token =
      options.token ||
      (typeof process !== "undefined" && process.env?.PHOENIX_TOKEN) ||
      "";

    this.timeout = options.timeout || 10000;
    this._sealPriv = null;
    this._sealPubB64 = null;
    this._nacl = null;

    const keyPath =
      options.sealKeyPath ||
      (typeof process !== "undefined" && process.env?.PHOENIX_SEAL_KEY);
    if (keyPath) {
      // Defer to setSealKey — errors surface on first resolve call
      this._pendingSealKey = this.setSealKey(keyPath).catch((err) => {
        this._sealKeyError = err;
      });
    }
  }

  /**
   * Load a seal private key, enabling sealed mode.
   * Requires the `tweetnacl` package.
   * @param {string} path - Path to the seal private key file
   */
  async setSealKey(path) {
    const fs = await import("node:fs/promises");
    const raw = (await fs.readFile(path, "utf8")).trim();
    const privBytes = Buffer.from(raw, "base64");
    if (privBytes.length !== 32) {
      throw new PhoenixError(
        `seal key must be 32 bytes, got ${privBytes.length}`
      );
    }

    try {
      this._nacl = (await import("tweetnacl")).default;
    } catch {
      throw new PhoenixError(
        "tweetnacl is required for sealed mode: npm install tweetnacl"
      );
    }

    this._sealPriv = privBytes;
    const keyPair = this._nacl.box.keyPair.fromSecretKey(
      new Uint8Array(privBytes)
    );
    this._sealPubB64 = Buffer.from(keyPair.publicKey).toString("base64");
  }

  /**
   * Check server health.
   * @returns {Promise<object>} Health status
   */
  async health() {
    return this._request("GET", "/v1/health");
  }

  /**
   * Resolve a single phoenix:// reference to its secret value.
   * @param {string} ref - A phoenix:// reference
   * @returns {Promise<string>} The plaintext secret value
   */
  async resolve(ref) {
    const result = await this.resolveBatch([ref]);
    if (result.errors && result.errors[ref]) {
      throw new PhoenixError(result.errors[ref]);
    }
    if (!result.values || !(ref in result.values)) {
      throw new PhoenixError(`no value returned for ${ref}`);
    }
    return result.values[ref];
  }

  /**
   * Resolve multiple phoenix:// references in one API call.
   * When sealed mode is enabled, responses are auto-decrypted transparently.
   * @param {string[]} refs - List of phoenix:// references
   * @returns {Promise<{values: Object<string,string>, errors?: Object<string,string>}>}
   */
  async resolveBatch(refs) {
    if (!refs || refs.length === 0) {
      throw new PhoenixError("refs must not be empty");
    }
    if (this._pendingSealKey) {
      await this._pendingSealKey;
      this._pendingSealKey = null;
    }
    if (this._sealKeyError) {
      throw this._sealKeyError;
    }
    const result = await this._request("POST", "/v1/resolve", { refs });

    if (this._sealPriv && result.sealed_values) {
      result.values = {};
      for (const [ref, env] of Object.entries(result.sealed_values)) {
        if (env.ref !== ref) {
          throw new PhoenixError(
            `sealed envelope ref mismatch: map key "${ref}", envelope "${env.ref}"`
          );
        }
        result.values[ref] = this._unsealEnvelope(env);
      }
      delete result.sealed_values;
    }

    return result;
  }

  /**
   * Decrypt a sealed envelope using the loaded private key.
   * @param {object} env - Sealed envelope object
   * @returns {string} Decrypted value
   */
  _unsealEnvelope(env) {
    if (!this._nacl || !this._sealPriv) {
      throw new PhoenixError("sealed mode not configured");
    }
    if (env.version !== 1) {
      throw new PhoenixError(`unsupported seal version: ${env.version}`);
    }
    if (env.algorithm !== "x25519-xsalsa20-poly1305") {
      throw new PhoenixError(`unsupported seal algorithm: ${env.algorithm}`);
    }

    const ephPub = new Uint8Array(Buffer.from(env.ephemeral_key, "base64"));
    const nonce = new Uint8Array(Buffer.from(env.nonce, "base64"));
    const ciphertext = new Uint8Array(Buffer.from(env.ciphertext, "base64"));
    const privKey = new Uint8Array(this._sealPriv);

    const plaintext = this._nacl.box.open(ciphertext, nonce, ephPub, privKey);
    if (!plaintext) {
      throw new PhoenixError("decryption failed");
    }

    const payload = JSON.parse(new TextDecoder().decode(plaintext));
    if (payload.path !== env.path) {
      throw new PhoenixError("path mismatch in sealed envelope");
    }
    if (payload.ref !== env.ref) {
      throw new PhoenixError("ref mismatch in sealed envelope");
    }

    return payload.value;
  }

  /**
   * @param {string} method
   * @param {string} path
   * @param {object} [body]
   * @returns {Promise<object>}
   */
  async _request(method, path, body) {
    const url = `${this.server}${path}`;
    const headers = {};

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    if (this._sealPubB64) {
      headers["X-Phoenix-Seal-Key"] = this._sealPubB64;
    }

    const options = {
      method,
      headers,
      signal: AbortSignal.timeout(this.timeout),
    };

    if (body) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }

    let resp;
    try {
      resp = await fetch(url, options);
    } catch (err) {
      throw new PhoenixError(`server unreachable: ${err.message}`);
    }

    const text = await resp.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }

    if (!resp.ok) {
      const msg = (data && data.error) || `HTTP ${resp.status}`;
      throw new PhoenixError(msg, resp.status);
    }

    return data;
  }
}

module.exports = { PhoenixClient, PhoenixError };
