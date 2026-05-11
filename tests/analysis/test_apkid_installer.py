"""Tests for the APKiD pip-install helper."""

from __future__ import annotations

import io
from typing import List

import pytest

from apk_web.analysis import apkid_installer as inst


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, lines: List[str], rc: int) -> None:
        self.stdout = io.StringIO("".join(line + "\n" for line in lines))
        self._rc = rc

    def wait(self) -> int:
        return self._rc


def _popen_seq(*procs):
    procs = list(procs)

    def _factory(argv, **kwargs):
        if not procs:
            raise AssertionError("Popen called more times than expected")
        return procs.pop(0)

    return _factory


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_classify_yara_python_dex_bug():
    log = (
        "Collecting apkid\n"
        "Collecting yara-python-dex\n"
        "FileNotFoundError: [Errno 2] No such file or directory: 'yara-python/README.rst'\n"
        "ERROR: Failed to build 'yara-python-dex'\n"
    )
    kind, hint = inst._classify(log, python_version="3.14.0")
    assert kind == "yara_python_dex_sdist_bug"
    assert "3.14" in hint
    assert "yara-python-dex" in hint


def test_classify_no_wheel():
    log = (
        "ERROR: Could not find a version that satisfies the requirement apkid\n"
        "ERROR: No matching distribution found for apkid\n"
    )
    kind, hint = inst._classify(log, python_version="3.14.0")
    assert kind == "no_wheel"
    assert "3.14" in hint


def test_classify_permission():
    kind, _ = inst._classify("PermissionError: [Errno 13] Permission denied", python_version="3.12")
    assert kind == "permission_denied"


def test_classify_network():
    kind, _ = inst._classify(
        "WARNING: Could not connect to pypi.org", python_version="3.12"
    )
    assert kind == "network"


def test_classify_default():
    kind, hint = inst._classify("weird unknown failure", python_version="3.12")
    assert kind == "error"
    assert hint  # always provides something


# ---------------------------------------------------------------------------
# install_streaming
# ---------------------------------------------------------------------------


def test_streaming_skips_pip_when_apkid_already_installed(monkeypatch):
    monkeypatch.setattr(inst, "_already_installed", lambda: True)
    # Popen must not be called at all in this branch.
    monkeypatch.setattr(
        inst.subprocess, "Popen", lambda *a, **kw: pytest.fail("Popen should not run")
    )
    lines = list(inst.install_streaming())
    assert lines[-1] == "[result ok]"
    assert any("already importable" in l for l in lines)


def test_streaming_succeeds_on_wheel_attempt(monkeypatch):
    states = iter([False, True])  # first not installed, then installed
    monkeypatch.setattr(inst, "_already_installed", lambda: next(states))
    monkeypatch.setattr(
        inst.subprocess,
        "Popen",
        _popen_seq(_FakeProc(["Collecting apkid", "Successfully installed apkid-3.1.0"], 0)),
    )
    lines = list(inst.install_streaming())
    assert lines[-1] == "[result ok]"
    assert any("--only-binary=:all:" in l for l in lines)


def test_streaming_auto_mode_stops_after_wheel_failure(monkeypatch):
    """In ``auto`` mode we don't run the broken sdist build automatically."""
    monkeypatch.setattr(inst, "_already_installed", lambda: False)
    popen = _popen_seq(_FakeProc(["No matching distribution found"], 1))
    monkeypatch.setattr(inst.subprocess, "Popen", popen)
    lines = list(inst.install_streaming())
    cmd_lines = [l for l in lines if l.startswith("[client] $ ")]
    assert len(cmd_lines) == 1
    assert "--only-binary=:all:" in cmd_lines[0]
    assert lines[-1].startswith("[result error no_wheel")


def test_streaming_with_strategy_source_skips_wheel_attempt(monkeypatch):
    monkeypatch.setattr(inst, "_already_installed", lambda: False)
    popen = _popen_seq(_FakeProc(["Building wheel for yara-python-dex"], 1))
    monkeypatch.setattr(inst.subprocess, "Popen", popen)
    lines = list(inst.install_streaming(strategy="source"))
    cmd_lines = [l for l in lines if l.startswith("[client] $ ")]
    assert len(cmd_lines) == 1
    assert "--only-binary" not in cmd_lines[0]


def test_streaming_force_source_legacy_flag(monkeypatch):
    monkeypatch.setattr(inst, "_already_installed", lambda: False)
    popen = _popen_seq(_FakeProc(["err"], 1))
    monkeypatch.setattr(inst.subprocess, "Popen", popen)
    lines = list(inst.install_streaming(force_source=True))
    cmd_lines = [l for l in lines if l.startswith("[client] $ ")]
    assert len(cmd_lines) == 1
    assert "--only-binary" not in cmd_lines[0]


def test_streaming_git_source_runs_three_pip_calls(monkeypatch):
    states = iter([False, True])
    monkeypatch.setattr(inst, "_already_installed", lambda: next(states))
    popen = _popen_seq(
        _FakeProc(["Successfully installed setuptools wheel"], 0),
        _FakeProc(["Successfully installed yara-python-dex"], 0),
        _FakeProc(["Successfully installed apkid-3.1.0"], 0),
    )
    monkeypatch.setattr(inst.subprocess, "Popen", popen)
    lines = list(inst.install_streaming(strategy="git_source"))
    cmds = [l for l in lines if l.startswith("[client] $ ")]
    assert len(cmds) == 3
    assert any("setuptools" in c and "wheel" in c for c in cmds)
    assert any("--no-build-isolation" in c and "yara-python-dex" in c for c in cmds)
    assert any(c.endswith(" apkid") or c.endswith(" --upgrade apkid") for c in cmds)
    assert lines[-1] == "[result ok]"


def test_streaming_git_source_stops_on_first_failure(monkeypatch):
    monkeypatch.setattr(inst, "_already_installed", lambda: False)
    popen = _popen_seq(
        _FakeProc(["ERROR: could not connect to pypi.org"], 1),
    )
    monkeypatch.setattr(inst.subprocess, "Popen", popen)
    lines = list(inst.install_streaming(strategy="git_source"))
    cmds = [l for l in lines if l.startswith("[client] $ ")]
    assert len(cmds) == 1  # bailed out after setuptools step failed
    assert lines[-1].startswith("[result error ")


def test_classify_missing_build_backend():
    log = (
        "BackendUnavailable: Cannot import 'setuptools.build_meta'\n"
        "Some other line\n"
    )
    kind, hint = inst._classify(log, python_version="3.14.0")
    assert kind == "missing_build_backend"
    assert "setuptools" in hint.lower()


def test_classify_resolution_impossible_on_python_314():
    """Real failure tail seen on Python 3.14 with pip >= 25."""
    log = (
        "ERROR: Cannot install apkid==0.9.3, apkid==3.1.0 because these "
        "package versions have conflicting dependencies.\n"
        "Additionally, some packages in these conflicts have no matching "
        "distributions available for your environment:\n"
        "    yara-python\n    yara-python-dex\n"
        "ERROR: ResolutionImpossible: for help visit ...\n"
    )
    kind, hint = inst._classify(log, python_version="3.14.0")
    assert kind == "no_wheel"
    assert "wheel" in hint.lower() or "github" in hint.lower()


def test_streaming_handles_spawn_failure(monkeypatch):
    monkeypatch.setattr(inst, "_already_installed", lambda: False)

    def boom(*a, **kw):
        raise OSError("pip not found")

    monkeypatch.setattr(inst.subprocess, "Popen", boom)
    lines = list(inst.install_streaming())
    assert lines[-1].startswith("[result error ")
    assert any("failed to spawn process" in l for l in lines)


# ---------------------------------------------------------------------------
# install_blocking
# ---------------------------------------------------------------------------


def test_blocking_success_returns_install_result(monkeypatch):
    states = iter([False, True])
    monkeypatch.setattr(inst, "_already_installed", lambda: next(states))
    monkeypatch.setattr(
        inst.subprocess,
        "Popen",
        _popen_seq(_FakeProc(["Successfully installed apkid-3.1.0"], 0)),
    )

    class _Spec:
        origin = "/tmp/site-packages/apkid/__init__.py"

    monkeypatch.setattr(inst.importlib.util, "find_spec", lambda _n: _Spec())

    result = inst.install_blocking()
    assert result.ok is True
    assert result.installed is True
    assert result.binary_path and result.binary_path.endswith("__init__.py")
    assert "[result ok]" in result.log


def test_blocking_failure_classifies_yara_bug(monkeypatch):
    monkeypatch.setattr(inst, "_already_installed", lambda: False)
    monkeypatch.setattr(
        inst.subprocess,
        "Popen",
        _popen_seq(
            _FakeProc(
                [
                    "Building wheels for collected packages: yara-python-dex",
                    "FileNotFoundError: [Errno 2] No such file or directory: 'yara-python/README.rst'",
                ],
                1,
            ),
        ),
    )
    result = inst.install_blocking(strategy="source")
    assert result.ok is False
    assert result.error_kind == "yara_python_dex_sdist_bug"
    assert result.hint and "yara-python-dex" in result.hint
    assert result.python_version  # filled in


# ---------------------------------------------------------------------------
# Route integration (uses the existing authed_client fixture)
# ---------------------------------------------------------------------------


def _authed_client(monkeypatch, tmp_path):
    """Local mini-fixture so we don't need to import tests/plugins/conftest."""
    monkeypatch.setenv("DASHBOARD_PASSWORD", "x")
    monkeypatch.setenv("AUTO_DOWNLOAD_TOOLS", "0")
    monkeypatch.setenv("ENABLE_ANALYSIS", "0")
    monkeypatch.setenv("ENABLE_PLUGINS", "0")
    monkeypatch.setenv("WORKSPACES_ROOT", str(tmp_path / "ws"))
    from apk_web.app import create_app

    app = create_app()
    app.testing = True
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    return app, client


def test_apkid_install_json_endpoint_success(monkeypatch, tmp_path):
    _app, client = _authed_client(monkeypatch, tmp_path)
    from apk_web.analysis import apkid_installer as inst_mod

    monkeypatch.setattr(
        inst_mod,
        "install_blocking",
        lambda **_: inst_mod.InstallResult(
            ok=True,
            installed=True,
            binary_path="/tmp/apkid/__init__.py",
            log="ok",
            python_version="3.12.0",
        ),
    )
    res = client.post(
        "/api/analysis/tools/apkid",
        json={"action": "install"},
    )
    assert res.status_code == 200
    body = res.get_json()
    assert body["ok"] is True
    assert body["installed"] is True


def test_apkid_install_json_endpoint_classifies_failure(monkeypatch, tmp_path):
    _app, client = _authed_client(monkeypatch, tmp_path)
    from apk_web.analysis import apkid_installer as inst_mod

    monkeypatch.setattr(
        inst_mod,
        "install_blocking",
        lambda **_: inst_mod.InstallResult(
            ok=False,
            installed=False,
            binary_path=None,
            log="boom",
            error="pip install failed",
            error_kind="yara_python_dex_sdist_bug",
            hint="install via py3.11",
            python_version="3.14.0",
        ),
    )
    res = client.post(
        "/api/analysis/tools/apkid",
        json={"action": "install"},
    )
    assert res.status_code == 500
    body = res.get_json()
    assert body["ok"] is False
    assert body["error_kind"] == "yara_python_dex_sdist_bug"
    assert body["python_version"] == "3.14.0"


def test_apkid_install_stream_endpoint(monkeypatch, tmp_path):
    _app, client = _authed_client(monkeypatch, tmp_path)
    from apk_web.analysis import apkid_installer as inst_mod

    monkeypatch.setattr(
        inst_mod,
        "install_streaming",
        lambda **_: iter(["[client] $ pip install apkid", "Collecting apkid", "[result ok]"]),
    )
    res = client.post(
        "/api/analysis/tools/apkid/install/stream",
        json={"force_source": False},
    )
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert "[result ok]" in text
    assert "Collecting apkid" in text


def test_apkid_install_stream_endpoint_passes_force_source(monkeypatch, tmp_path):
    _app, client = _authed_client(monkeypatch, tmp_path)
    from apk_web.analysis import apkid_installer as inst_mod

    received = {}

    def fake_stream(*, force_source=False, strategy="auto"):
        received["force_source"] = force_source
        received["strategy"] = strategy
        return iter(["[result error error]"])

    monkeypatch.setattr(inst_mod, "install_streaming", fake_stream)
    client.post(
        "/api/analysis/tools/apkid/install/stream",
        json={"force_source": True, "strategy": "git_source"},
    )
    assert received["force_source"] is True
    assert received["strategy"] == "git_source"
