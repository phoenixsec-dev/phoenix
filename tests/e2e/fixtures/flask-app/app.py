from flask import Flask, request, jsonify
import os

app = Flask(__name__)
EXPECTED = os.getenv("APP_API_KEY", "dev-key")

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/protected")
def protected():
    provided = request.headers.get("X-API-Key", "")
    if provided != EXPECTED:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True, "message": "authorized"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
