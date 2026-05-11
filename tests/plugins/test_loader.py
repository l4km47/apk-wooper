from __future__ import annotations

import json
from pathlib import Path

from flask import Blueprint


def _write_fake_plugin(root: Path, plugin_id: str) -> Path:
    folder = root / plugin_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "__init__.py").write_text("", encoding="utf-8")
    (folder / "plugin.py").write_text(
        (
            "from flask import Blueprint\n"
            "from apk_web.plugins.registry import Plugin\n"
            "bp = Blueprint('fake', __name__)\n"
            "@bp.route('/')\n"
            "def fake_index():\n"
            "    return 'hello fake'\n"
            f"PLUGIN = Plugin(id='{plugin_id}', name='Fake plugin', blueprint=bp,\n"
            "                accepts=['secret.firebase_api_key'])\n"
        ),
        encoding="utf-8",
    )
    return folder


def test_external_path_drops_in_a_plugin(tmp_path, monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "x")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ENABLE_ANALYSIS", "0")

    pkg_dir = tmp_path / "ext"
    _write_fake_plugin(pkg_dir, "myplug")

    config_path = tmp_path / "plugins.json"
    config_path.write_text(
        json.dumps(
            {
                "enabled": [],
                "disabled": [],
                "external": [
                    {
                        "id": "myplug",
                        "name": "My Plugin",
                        "external_path": str(pkg_dir / "myplug"),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PLUGINS_CONFIG", str(config_path))

    from apk_web.app import create_app

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True

    res = client.get("/api/plugins")
    assert res.status_code == 200
    payload = res.get_json()
    ids = {p["id"] for p in payload["plugins"]}
    assert "myplug" in ids
    assert payload["errors"] == []

    # The plugin's own root should be reachable directly.
    res = client.get("/plugins/myplug/")
    assert res.status_code == 200
    assert b"hello fake" in res.data


def test_load_failure_is_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "x")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ENABLE_ANALYSIS", "0")

    pkg_dir = tmp_path / "broken"
    pkg_dir.mkdir()
    (pkg_dir / "plugin.py").write_text("raise RuntimeError('boom')\n", encoding="utf-8")

    config_path = tmp_path / "plugins.json"
    config_path.write_text(
        json.dumps(
            {
                "enabled": [],
                "disabled": [],
                "external": [
                    {"id": "broken", "external_path": str(pkg_dir)},
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PLUGINS_CONFIG", str(config_path))

    from apk_web.app import create_app

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True

    res = client.get("/api/plugins")
    data = res.get_json()
    assert any(err["source"] == "broken" for err in data["errors"])
    # And the app still serves /api/plugins, i.e. broken plugin didn't take it down.
    assert res.status_code == 200


def test_factory_mount_uses_wsgi_dispatcher(tmp_path, monkeypatch):
    """External app supplied as a ``factory`` is mounted under ``/_app/``."""
    monkeypatch.setenv("DASHBOARD_PASSWORD", "x")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ENABLE_ANALYSIS", "0")

    # A tiny Flask app exposed via create_app().
    pkg_root = tmp_path / "ext_factory"
    pkg_root.mkdir()
    pkg = pkg_root / "mini_app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        (
            "from flask import Flask\n"
            "def create_app():\n"
            "    app = Flask(__name__)\n"
            "    @app.route('/')\n"
            "    def index():\n"
            "        return 'from mini'\n"
            "    @app.route('/whoami')\n"
            "    def whoami():\n"
            "        return 'mini-app'\n"
            "    return app\n"
        ),
        encoding="utf-8",
    )

    config_path = tmp_path / "plugins.json"
    config_path.write_text(
        json.dumps(
            {
                "enabled": [],
                "disabled": [],
                "external": [
                    {
                        "id": "mini",
                        "name": "Mini",
                        "external_path": str(pkg_root),
                        "module": "mini_app",
                        "factory": "create_app",
                        "mode": "iframe",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PLUGINS_CONFIG", str(config_path))

    from apk_web.app import create_app

    app = create_app()
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True

    # The wrapper page renders an iframe pointing at /plugins/mini/_app/.
    res = client.get("/plugins/mini")
    assert res.status_code == 200
    assert b"/plugins/mini/_app/" in res.data

    # The sub-app is reachable when authenticated.
    res = client.get("/plugins/mini/_app/")
    assert res.status_code == 200
    assert b"from mini" in res.data
    res = client.get("/plugins/mini/_app/whoami")
    assert res.status_code == 200
    assert res.data == b"mini-app"


def test_factory_mount_requires_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "x")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ENABLE_ANALYSIS", "0")

    pkg_root = tmp_path / "ext_secret"
    pkg_root.mkdir()
    pkg = pkg_root / "secret_app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        (
            "from flask import Flask\n"
            "def create_app():\n"
            "    app = Flask(__name__)\n"
            "    @app.route('/')\n"
            "    def index():\n"
            "        return 'secret'\n"
            "    return app\n"
        ),
        encoding="utf-8",
    )

    config_path = tmp_path / "plugins.json"
    config_path.write_text(
        json.dumps(
            {
                "enabled": [],
                "disabled": [],
                "external": [
                    {
                        "id": "sec",
                        "external_path": str(pkg_root),
                        "module": "secret_app",
                        "factory": "create_app",
                        "mode": "iframe",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PLUGINS_CONFIG", str(config_path))

    from apk_web.app import create_app

    app = create_app()
    client = app.test_client()  # NOT authenticated
    res = client.get("/plugins/sec/_app/")
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/login")
