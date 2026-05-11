"""Flask blueprint for the built-in MobSF plugin."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import urlparse

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    stream_with_context,
)

from apk_web.auth import login_required
from apk_web.plugins.mobsf.client import (
    MobsfClient,
    MobsfError,
    load_config,
    save_config,
)
from apk_web.plugins.mobsf import github_installer as gh_installer


_LOG = logging.getLogger(__name__)

bp = Blueprint(
    "mobsf",
    __name__,
    template_folder=str(Path(__file__).resolve().parent / "templates"),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_config() -> Dict[str, str]:
    cfg = load_config(
        current_app.instance_path,
        env_url=str(current_app.config.get("MOBSF_URL") or ""),
        env_api_key=str(current_app.config.get("MOBSF_API_KEY") or ""),
    )
    return cfg


def _client() -> Tuple[MobsfClient, Dict[str, str]]:
    cfg = _resolve_config()
    return MobsfClient(cfg.get("url", ""), cfg.get("api_key", "")), cfg


def _ping_for_template() -> Dict[str, Any]:
    client, cfg = _client()
    ok, message = client.ping()
    return {
        "ok": ok,
        "message": message,
        "url": cfg.get("url", ""),
        "api_key_set": bool(cfg.get("api_key")),
    }


def _job_apk(job_id: str) -> Path:
    store = current_app.extensions.get("job_store")
    if store is None:
        abort(503, "job store unavailable")
    if not job_id or "/" in job_id or "\\" in job_id or ".." in job_id:
        abort(400, "invalid job id")
    try:
        job_dir = store.job_dir(job_id)
    except KeyError:
        abort(404, "job not found")
    except Exception:  # noqa: BLE001
        abort(404, "job not found")
    apk = Path(job_dir) / "input.apk"
    if not apk.is_file():
        abort(404, "input.apk not found for job")
    return apk


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _tools_root() -> Path:
    raw = current_app.config.get("TOOLS_ROOT") or "tools"
    root = Path(str(raw))
    if not root.is_absolute():
        root = Path(current_app.root_path).parent / root
    return root


@bp.route("/", methods=["GET"])
@login_required
def index():
    status = _ping_for_template()
    deep_hash = (request.args.get("hash") or "").strip()
    iframe_url = status["url"] if status["ok"] else ""
    if status["ok"] and deep_hash:
        iframe_url = f"{status['url'].rstrip('/')}/static_analyzer/?checksum={deep_hash}"
    github = None
    if not status["ok"]:
        try:
            github = gh_installer.github_status(_tools_root()).to_dict()
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("github_status failed: %s", exc)
            github = {"error": str(exc)}
    return render_template(
        "mobsf/index.html",
        plugin={"name": "MobSF", "source": "builtin", "version": "1.0.0"},
        status=status,
        iframe_url=iframe_url,
        deep_hash=deep_hash,
        github=github,
    )


@bp.route("/status", methods=["GET"])
@login_required
def status():
    return jsonify(_ping_for_template())


@bp.route("/config", methods=["GET"])
@login_required
def config_get():
    cfg = _resolve_config()
    masked = dict(cfg)
    if masked.get("api_key"):
        key = masked["api_key"]
        masked["api_key_preview"] = (
            f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "***"
        )
    return jsonify({"ok": True, "config": masked})


@bp.route("/config", methods=["POST"])
@login_required
def config_post():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url") or "").strip()
    api_key = str(body.get("api_key") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "url is required"}), 400
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return jsonify({"ok": False, "error": "url must be http(s)://host:port"}), 400
    saved = save_config(current_app.instance_path, url, api_key)
    return jsonify({"ok": True, "config": saved})


@bp.route("/detect", methods=["POST"])
@login_required
def detect():
    """Probe MobSF using a candidate URL+key without persisting."""
    body = request.get_json(silent=True) or {}
    url = str(body.get("url") or "").strip()
    api_key = str(body.get("api_key") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "url is required"}), 400
    client = MobsfClient(url, api_key)
    ok, message = client.ping()
    if ok and body.get("persist"):
        save_config(current_app.instance_path, url, api_key)
    return jsonify({"ok": ok, "message": message, "url": url})


@bp.route("/scan/<job_id>", methods=["POST"])
@login_required
def scan(job_id: str):
    apk = _job_apk(job_id)
    client, cfg = _client()
    ok, message = client.ping()
    if not ok:
        return (
            jsonify(
                {
                    "ok": False,
                    "error": f"MobSF is not reachable at {cfg.get('url')}: {message}",
                }
            ),
            502,
        )
    try:
        upload = client.upload(apk)
    except MobsfError as exc:
        _LOG.warning("mobsf upload failed for %s: %s", job_id, exc)
        return jsonify({"ok": False, "error": str(exc)}), 502

    hash_value = str(upload.get("hash") or "")
    scan_type = str(upload.get("scan_type") or "apk")
    file_name = str(upload.get("file_name") or apk.name)
    if not hash_value:
        return jsonify({"ok": False, "error": "MobSF did not return a hash"}), 502

    try:
        result = client.scan(scan_type, file_name, hash_value)
    except MobsfError as exc:
        _LOG.warning("mobsf scan failed for %s: %s", job_id, exc)
        return jsonify({"ok": False, "error": str(exc)}), 502

    return jsonify(
        {
            "ok": True,
            "hash": hash_value,
            "scan_type": scan_type,
            "file_name": file_name,
            "report_url": client.report_url(hash_value),
            "raw": result,
        }
    )


# ---------------------------------------------------------------------------
# GitHub-driven install / start / stop (no Docker, no admin needed)
# ---------------------------------------------------------------------------


@bp.route("/github/status", methods=["GET"])
@login_required
def github_status_route():
    return jsonify({"ok": True, "github": gh_installer.github_status(_tools_root()).to_dict()})


def _stream_response(gen):
    return Response(
        stream_with_context(gen),
        mimetype="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@bp.route("/github/clone", methods=["POST"])
@login_required
def github_clone_route():
    """Stream ``git clone`` output line-by-line."""
    tools_root = _tools_root()

    def _gen():
        for line in gh_installer.clone_stream(tools_root):
            yield (line + "\n")

    return _stream_response(_gen())


@bp.route("/github/setup", methods=["POST"])
@login_required
def github_setup_route():
    """Stream MobSF's setup.sh / setup.bat output."""
    tools_root = _tools_root()

    def _gen():
        for line in gh_installer.setup_stream(tools_root):
            yield (line + "\n")

    return _stream_response(_gen())


@bp.route("/github/start", methods=["POST"])
@login_required
def github_start_route():
    body = request.get_json(silent=True) or {}
    raw_port = body.get("host_port", gh_installer.DEFAULT_HOST_PORT)
    try:
        host_port = int(raw_port)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "host_port must be an integer"}), 400
    if not (1 <= host_port <= 65535):
        return jsonify({"ok": False, "error": "host_port out of range"}), 400

    tools_root = _tools_root()
    ok, message, details = gh_installer.start(tools_root, host_port=host_port)
    response: Dict[str, Any] = {"ok": ok, "message": message, **details}

    if ok:
        try:
            current_cfg = load_config(
                current_app.instance_path,
                env_url=str(current_app.config.get("MOBSF_URL") or ""),
                env_api_key=str(current_app.config.get("MOBSF_API_KEY") or ""),
            )
            new_url = f"http://localhost:{details.get('host_port', host_port)}"
            if current_cfg.get("url") != new_url:
                save_config(
                    current_app.instance_path,
                    new_url,
                    current_cfg.get("api_key", ""),
                )
                response["url_updated"] = new_url
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("could not persist MobSF URL after start: %s", exc)
    status = 200 if ok else 502
    return jsonify(response), status


@bp.route("/github/stop", methods=["POST"])
@login_required
def github_stop_route():
    ok, message = gh_installer.stop(_tools_root())
    status = 200 if ok else 502
    return jsonify({"ok": ok, "message": message}), status


@bp.route("/github/log", methods=["GET"])
@login_required
def github_log_route():
    tail = gh_installer.tail_log(_tools_root())
    return Response(tail, mimetype="text/plain; charset=utf-8")
