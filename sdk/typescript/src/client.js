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
   * @param {string[]} refs - List of phoenix:// references
   * @returns {Promise<{values: Object<string,string>, errors?: Object<string,string>}>}
   */
  async resolveBatch(refs) {
    if (!refs || refs.length === 0) {
      throw new PhoenixError("refs must not be empty");
    }
    return this._request("POST", "/v1/resolve", { refs });
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
