"""Firebase tester plugin manifest."""
from __future__ import annotations

from apk_web.plugins.firebase.routes import bp
from apk_web.plugins.registry import Plugin

PLUGIN = Plugin(
    id="firebase",
    name="Firebase tester",
    description=(
        "Probe Firebase Realtime Database endpoints discovered in decompiled APKs: "
        "test connectivity, dump open databases, restore JSON snapshots, run "
        "custom REST requests, and generate XSS test payloads."
    ),
    version="1.0.0",
    source="builtin",
    mode="native",
    accepts=[
        "secret.firebase_api_key",
        "secret.fcm_server_key",
        "secret.google_api_key",
    ],
    blueprint=bp,
)
