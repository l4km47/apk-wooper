"""Blueprint serving the plugins index and iframe wrappers.

This blueprint is registered separately from individual plugin blueprints; it
owns the ``/plugins`` and ``/plugins/<id>`` URLs **for the wrapper UI**. Plugin
blueprints themselves are mounted at ``/plugins/<id>/...`` (note the trailing
slash) so the index page can route to a plugin's own ``/`` while this blueprint
provides ``/plugins`` and ``/plugins/<id>`` (no trailing slash) for wrappers.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict

from flask import Blueprint, abort, current_app, render_template, request

from apk_web.auth import login_required
from apk_web.plugins.loader import get_registry

plugins_bp = Blueprint("plugins", __name__, url_prefix="/plugins")


@plugins_bp.route("/", methods=["GET"])
@login_required
def plugins_index():
    registry = get_registry(current_app)
    items = [p.to_public_dict(healthy=_health(p)) for p in registry.all()]
    return render_template("plugins/index.html", plugins=items, load_errors=registry.errors())


@plugins_bp.route("/<plugin_id>", methods=["GET"])
@login_required
def plugin_entry(plugin_id: str):
    """Entry-point URL for a plugin.

    The exact URL is ``/plugins/<id>`` (no trailing slash). For:

    * Blueprint plugins in ``native`` mode -- redirect to the plugin's own
      ``/plugins/<id>/`` index (its blueprint owns that).
    * Plugins that need an iframe wrapper (``iframe`` mode or a WSGI sub-app
      mounted under ``/plugins/<id>/_app/``) -- render ``plugins/iframe.html``
      around the right inner URL.
    """
    registry = get_registry(current_app)
    plugin = registry.get(plugin_id)
    if plugin is None:
        abort(404)

    is_wsgi = plugin.wsgi_app is not None
    inner_root = f"/plugins/{plugin_id}/_app/" if is_wsgi else f"/plugins/{plugin_id}/"

    if plugin.mode == "native" and not is_wsgi:
        # Native plugins render their own page; let them handle the prefill.
        target = inner_root
        if request.args.get("prefill"):
            target = f"{target}?prefill={request.args.get('prefill')}"
        return current_app.redirect(target)

    prefill = _decode_prefill(request.args.get("prefill"))
    iframe_url = inner_root
    if request.args.get("prefill"):
        sep = "&" if "?" in iframe_url else "?"
        iframe_url = f"{iframe_url}{sep}prefill={request.args.get('prefill')}"
    return render_template(
        "plugins/iframe.html",
        plugin=plugin.to_public_dict(healthy=_health(plugin)),
        iframe_url=iframe_url,
        prefill=prefill,
    )


def _decode_prefill(raw: str | None) -> Dict[str, Any] | None:
    if not raw:
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        data = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(data.decode("utf-8"))
        if isinstance(parsed, dict):
            return parsed
    except Exception:  # noqa: BLE001
        return None
    return None


def _health(plugin) -> Dict[str, Any]:
    if not plugin.health:
        return {"ok": True, "message": ""}
    try:
        result = plugin.health() or {}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "message": f"health check raised: {exc}"}
    return {
        "ok": bool(result.get("ok", True)),
        "message": str(result.get("message") or ""),
    }
