"""MobSF plugin manifest."""

from __future__ import annotations

from typing import Any, Dict

from apk_web.plugins.mobsf.client import MobsfClient, load_config
from apk_web.plugins.mobsf.routes import bp
from apk_web.plugins.registry import Plugin


def _health() -> Dict[str, Any]:
    """Lightweight health probe shown by the plugins UI."""
    try:
        from flask import current_app

        cfg = load_config(
            current_app.instance_path,
            env_url=str(current_app.config.get("MOBSF_URL") or ""),
            env_api_key=str(current_app.config.get("MOBSF_API_KEY") or ""),
        )
    except Exception:  # noqa: BLE001
        return {"ok": False, "message": "MobSF config unavailable"}
    client = MobsfClient(cfg.get("url", ""), cfg.get("api_key", ""), timeout=4.0)
    ok, message = client.ping()
    return {"ok": ok, "message": message}


PLUGIN = Plugin(
    id="mobsf",
    name="MobSF",
    description=(
        "Send APKs to a running Mobile Security Framework (MobSF) instance "
        "and embed its static-analysis report directly in the dashboard."
    ),
    version="1.0.0",
    source="builtin",
    mode="native",
    accepts=[
        "secret.firebase_api_key",
        "secret.google_api_key",
        "secret.facebook_app_id",
        "apkid.packer",
        "apkid.obfuscator",
        "apkid.anti_vm",
        "apkid.anti_debug",
    ],
    blueprint=bp,
    health=_health,
)
