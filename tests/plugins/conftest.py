from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

import pytest


@pytest.fixture
def isolated_plugins_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the plugin loader at a temp ``plugins.json`` instead of the repo one."""
    cfg = tmp_path / "plugins.json"
    cfg.write_text(json.dumps({"enabled": [], "disabled": [], "external": []}), encoding="utf-8")
    monkeypatch.setenv("PLUGINS_CONFIG", str(cfg))
    yield cfg


@pytest.fixture
def authed_client(monkeypatch: pytest.MonkeyPatch, isolated_plugins_config: Path):
    """A Flask test client with the user logged in and tools auto-download disabled."""
    monkeypatch.setenv("DASHBOARD_PASSWORD", "x")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ENABLE_ANALYSIS", "0")
    from apk_web.app import create_app

    app = create_app()
    app.testing = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    return app, client
