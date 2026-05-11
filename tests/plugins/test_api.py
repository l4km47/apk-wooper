from __future__ import annotations

import json
from pathlib import Path


def test_list_returns_firebase_builtin(authed_client):
    _app, client = authed_client
    res = client.get("/api/plugins")
    assert res.status_code == 200
    data = res.get_json()
    ids = {p["id"] for p in data["plugins"]}
    assert "firebase" in ids
    fb = next(p for p in data["plugins"] if p["id"] == "firebase")
    assert fb["source"] == "builtin"
    assert "secret.firebase_api_key" in fb["accepts"]


def test_external_add_remove_round_trip(authed_client, isolated_plugins_config: Path):
    _app, client = authed_client
    res = client.post(
        "/api/plugins/external",
        json={
            "id": "newone",
            "name": "New One",
            "external_path": "C:/somewhere",
            "module": "newone",
            "blueprint_attr": "bp",
            "mode": "iframe",
            "accepts": ["secret.openai_key"],
        },
    )
    assert res.status_code == 200, res.data
    cfg = json.loads(isolated_plugins_config.read_text(encoding="utf-8"))
    assert any(e["id"] == "newone" for e in cfg["external"])
    assert "newone" in cfg["enabled"]

    res = client.delete("/api/plugins/external/newone")
    assert res.status_code == 200
    cfg = json.loads(isolated_plugins_config.read_text(encoding="utf-8"))
    assert not any(e["id"] == "newone" for e in cfg["external"])


def test_external_add_rejects_missing_target(authed_client):
    _app, client = authed_client
    res = client.post("/api/plugins/external", json={"id": "x"})
    assert res.status_code == 400
    assert "error" in res.get_json()


def test_external_add_validates_id(authed_client):
    _app, client = authed_client
    res = client.post(
        "/api/plugins/external",
        json={"id": "bad id!", "module": "x"},
    )
    assert res.status_code == 400


def test_set_enabled_persists(authed_client, isolated_plugins_config: Path):
    _app, client = authed_client
    res = client.post("/api/plugins/firebase/enabled", json={"enabled": False})
    assert res.status_code == 200
    cfg = json.loads(isolated_plugins_config.read_text(encoding="utf-8"))
    assert "firebase" in cfg["disabled"]
    assert "firebase" not in cfg["enabled"]


def test_unauthenticated_returns_401(authed_client):
    app, _client = authed_client
    anon = app.test_client()
    res = anon.get("/api/plugins")
    assert res.status_code == 401
