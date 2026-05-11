"""Tests for plugin pip-dependency helpers + dashboard endpoints."""
from __future__ import annotations

from typing import List

import pytest

from apk_web.plugins import dependencies as plugin_deps
from apk_web.plugins.registry import Plugin, PluginRegistry


# ---------------------------------------------------------------------------
# Pure helper unit tests
# ---------------------------------------------------------------------------


def _plugin(plugin_id: str, requires: List[str]) -> Plugin:
    return Plugin(
        id=plugin_id,
        name=plugin_id.title(),
        description=f"{plugin_id} plugin",
        version="1.0.0",
        source="builtin",
        mode="native",
        pip_requires=list(requires),
    )


def test_parse_entry_handles_plain_name():
    assert plugin_deps._parse_entry("requests") == ("requests", "requests")


def test_parse_entry_lowercases_and_converts_dashes():
    assert plugin_deps._parse_entry("PyYAML") == ("PyYAML", "pyyaml")
    assert plugin_deps._parse_entry("google-cloud-storage") == (
        "google-cloud-storage",
        "google_cloud_storage",
    )


def test_parse_entry_respects_explicit_import_name():
    assert plugin_deps._parse_entry("pyyaml:yaml") == ("pyyaml", "yaml")
    # version specifiers are preserved on the pip side but ignored on import.
    assert plugin_deps._parse_entry("openai>=1.0:openai") == (
        "openai>=1.0",
        "openai",
    )


def test_parse_entry_rejects_empty():
    assert plugin_deps._parse_entry("") is None
    assert plugin_deps._parse_entry("   ") is None
    assert plugin_deps._parse_entry(":only_import") is None


def test_collect_returns_installed_flags(monkeypatch):
    p1 = _plugin("a", ["requests", "definitely_not_installed_xyz"])
    p2 = _plugin("b", ["sys"])  # 'sys' is always importable

    def fake_is_installed(name):
        return name in ("requests", "sys")

    monkeypatch.setattr(plugin_deps, "_is_installed", fake_is_installed)

    deps = plugin_deps.collect([p1, p2])
    by_pip = {d.pip: d for d in deps}
    assert by_pip["requests"].installed is True
    assert by_pip["definitely_not_installed_xyz"].installed is False
    assert by_pip["sys"].installed is True
    # Plugin attribution
    assert by_pip["requests"].plugin_id == "a"
    assert by_pip["sys"].plugin_id == "b"


def test_collect_skips_unparseable_entries(monkeypatch):
    p = _plugin("noop", ["", ":only_import", "valid_pkg"])
    monkeypatch.setattr(plugin_deps, "_is_installed", lambda _n: False)
    deps = plugin_deps.collect([p])
    assert [d.pip for d in deps] == ["valid_pkg"]


def test_allowed_pip_specs_returns_pip_part_only():
    p1 = _plugin("a", ["requests", "pyyaml:yaml"])
    p2 = _plugin("b", ["openai>=1.0:openai"])
    specs = plugin_deps.allowed_pip_specs([p1, p2])
    assert specs == {"requests", "pyyaml", "openai>=1.0"}


def test_install_streaming_empty_list_short_circuits():
    lines = list(plugin_deps.install_streaming([]))
    assert lines[-1] == "[result ok]"
    assert any("nothing to install" in l for l in lines)


def test_install_streaming_streams_pip_output(monkeypatch):
    class _Stdout:
        def __init__(self, lines):
            self._lines = iter(lines)
        def __iter__(self):
            return self._lines
        def close(self):
            pass

    class _Proc:
        def __init__(self):
            self.stdout = _Stdout(["Collecting requests\n", "Successfully installed requests-2.31\n"])
        def wait(self):
            return 0

    monkeypatch.setattr(plugin_deps.subprocess, "Popen", lambda *a, **kw: _Proc())
    lines = list(plugin_deps.install_streaming(["requests"]))
    assert any("Collecting requests" in l for l in lines)
    assert lines[-1] == "[result ok]"


def test_install_streaming_classifies_nonzero_exit(monkeypatch):
    class _Stdout:
        def __init__(self):
            self._lines = iter(["ERROR: blah\n"])
        def __iter__(self):
            return self._lines
        def close(self):
            pass
    class _Proc:
        def __init__(self):
            self.stdout = _Stdout()
        def wait(self):
            return 2
    monkeypatch.setattr(plugin_deps.subprocess, "Popen", lambda *a, **kw: _Proc())
    lines = list(plugin_deps.install_streaming(["doesntmatter"]))
    assert lines[-1] == "[result error rc2]"


def test_install_streaming_handles_spawn_failure(monkeypatch):
    def boom(*a, **kw):
        raise OSError("no pip here")
    monkeypatch.setattr(plugin_deps.subprocess, "Popen", boom)
    lines = list(plugin_deps.install_streaming(["x"]))
    assert lines[-1] == "[result error spawn]"
    assert any("failed to spawn pip" in l for l in lines)


# ---------------------------------------------------------------------------
# Route integration tests
# ---------------------------------------------------------------------------


def _install_fake_registry(monkeypatch, *plugins):
    """Replace the registry resolver used by the API routes."""
    registry = PluginRegistry()
    for p in plugins:
        registry.add(p)
    monkeypatch.setattr(
        "apk_web.routes.api._plugin_registry_or_none",
        lambda: registry,
    )
    return registry


def test_dependencies_list_endpoint(authed_client, monkeypatch):
    app, client = authed_client
    _install_fake_registry(
        monkeypatch,
        _plugin("alpha", ["requests", "definitely_missing"]),
        _plugin("beta", ["sys"]),
    )
    monkeypatch.setattr(
        plugin_deps,
        "_is_installed",
        lambda name: name in ("requests", "sys"),
    )
    res = client.get("/api/plugins/dependencies")
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    pips = {d["pip"]: d for d in body["dependencies"]}
    assert pips["requests"]["installed"] is True
    assert pips["definitely_missing"]["installed"] is False
    assert body["missing_count"] == 1


def test_dependencies_install_rejects_unknown_packages(authed_client, monkeypatch):
    app, client = authed_client
    _install_fake_registry(monkeypatch, _plugin("alpha", ["requests"]))
    res = client.post(
        "/api/plugins/dependencies/install",
        json={"packages": ["malicious-pkg"]},
    )
    assert res.status_code == 400
    body = res.get_json()
    assert body["ok"] is False
    assert "malicious-pkg" in body["disallowed"]


def test_dependencies_install_rejects_empty_list(authed_client, monkeypatch):
    app, client = authed_client
    _install_fake_registry(monkeypatch, _plugin("alpha", ["requests"]))
    res = client.post("/api/plugins/dependencies/install", json={"packages": []})
    assert res.status_code == 400


def test_dependencies_install_streams_allowed_packages(authed_client, monkeypatch):
    app, client = authed_client
    _install_fake_registry(monkeypatch, _plugin("alpha", ["requests"]))

    received = {}

    def fake_stream(packages):
        received["packages"] = list(packages)
        yield "[client] $ pip install requests"
        yield "Successfully installed requests-2.31.0"
        yield "[result ok]"

    monkeypatch.setattr(plugin_deps, "install_streaming", fake_stream)
    res = client.post(
        "/api/plugins/dependencies/install",
        json={"packages": ["requests"]},
    )
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "[result ok]" in text
    assert received["packages"] == ["requests"]
