"""Local web app: type a prompt, watch it move through the model's layers.

Usage:  python app.py     then open http://127.0.0.1:5000
"""

import json
from functools import lru_cache
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import inspector

HERE = Path(__file__).parent
MAX_PROMPT_CHARS = 300

app = Flask(__name__)


@lru_cache(maxsize=None)
def get_model(name):
    return inspector.load(name)


@app.get("/")
def index():
    return send_from_directory(HERE / "static", "index.html")


@app.post("/api/inspect")
def inspect():
    body = request.get_json(silent=True) or {}
    name, prompt = body.get("model"), body.get("prompt")
    if name not in inspector.MODELS:
        return jsonify(error=f"model must be one of {sorted(inspector.MODELS)}"), 400
    if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > MAX_PROMPT_CHARS:
        return jsonify(error=f"prompt must be 1-{MAX_PROMPT_CHARS} characters"), 400
    if name == "backdoored" and not Path(inspector.MODELS[name]).exists():
        return jsonify(error="The backdoored model isn't built yet. Run: python plant_backdoor.py"), 404

    model, tok = get_model(name)
    return jsonify(trace=inspector.trace(model, tok, prompt),
                   importance=inspector.word_importance(model, tok, prompt))


@app.get("/api/scan")
def scan():
    path = HERE / "results" / "results.json"
    if not path.exists():
        return jsonify(error="No scan results yet. Run: python run_demo.py"), 404
    return jsonify(json.loads(path.read_text(encoding="utf-8")))


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
