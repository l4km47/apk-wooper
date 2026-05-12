"""Tests for the build helpers under ``scripts/``."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# bootstrap_all_tools
# ---------------------------------------------------------------------------


def test_bootstrap_all_tools_respects_env_flags(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Tool installs only fire when their ENABLE_* flag is true in .env."""

    monkeypatch.setenv("TOOLS_ROOT", str(tmp_path))
    monkeypatch.setenv("ENABLE_GITLEAKS", "true")
    monkeypatch.setenv("ENABLE_TRUFFLEHOG", "false")
    monkeypatch.setenv("ENABLE_RADARE2", "false")

    calls: dict[str, int] = {"decompiler": 0, "gitleaks": 0, "trufflehog": 0, "radare2": 0}

    def fake_decompiler(root, *, logger=None):
        calls["decompiler"] += 1
        return {"jadx": False, "apktool": False}

    def fake_gitleaks(root, *, logger=None):
        calls["gitleaks"] += 1
        return root / "gitleaks" / "gitleaks.exe"

    def fake_trufflehog(root, *, logger=None):
        calls["trufflehog"] += 1
        return root / "trufflehog" / "trufflehog.exe"

    def fake_radare2(root, *, logger=None):
        calls["radare2"] += 1
        return root / "radare2" / "r2.exe"

    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_decompiler_tools", fake_decompiler)
    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_gitleaks", fake_gitleaks)
    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_trufflehog", fake_trufflehog)
    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_radare2", fake_radare2)

    from scripts import bootstrap_all_tools

    assert bootstrap_all_tools.main([]) == 0
    assert calls == {"decompiler": 1, "gitleaks": 1, "trufflehog": 0, "radare2": 0}


def test_bootstrap_all_tools_swallows_failures(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("TOOLS_ROOT", str(tmp_path))
    monkeypatch.setenv("ENABLE_GITLEAKS", "true")
    monkeypatch.setenv("ENABLE_TRUFFLEHOG", "false")
    monkeypatch.setenv("ENABLE_RADARE2", "false")

    def fake_decompiler(root, *, logger=None):
        raise RuntimeError("offline")

    def fake_gitleaks(root, *, logger=None):
        raise RuntimeError("nope")

    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_decompiler_tools", fake_decompiler)
    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_gitleaks", fake_gitleaks)
    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_trufflehog", lambda *a, **k: None)
    monkeypatch.setattr("apk_web.tools_bootstrap.ensure_radare2", lambda *a, **k: None)

    from scripts import bootstrap_all_tools

    # Optional steps are best-effort: warnings only, never a hard failure.
    assert bootstrap_all_tools.main([]) == 0


# ---------------------------------------------------------------------------
# bootstrap_plugins
# ---------------------------------------------------------------------------


def test_bootstrap_plugins_writes_empty_plugins_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    cfg = tmp_path / "plugins.json"
    monkeypatch.setenv("ENABLE_PLUGINS", "true")
    monkeypatch.setenv("ENABLE_MOBSF", "false")
    monkeypatch.setenv("PLUGINS_CONFIG", str(cfg))

    from scripts import bootstrap_plugins

    assert bootstrap_plugins.main([]) == 0
    assert cfg.is_file()
    payload = json.loads(cfg.read_text(encoding="utf-8"))
    assert payload == {"enabled": [], "disabled": [], "external": []}


def test_bootstrap_plugins_preserves_existing_plugins_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    cfg = tmp_path / "plugins.json"
    cfg.write_text(
        json.dumps({"enabled": ["firebase"], "disabled": [], "external": []}),
        encoding="utf-8",
    )

    monkeypatch.setenv("ENABLE_PLUGINS", "true")
    monkeypatch.setenv("ENABLE_MOBSF", "false")
    monkeypatch.setenv("PLUGINS_CONFIG", str(cfg))

    from scripts import bootstrap_plugins

    assert bootstrap_plugins.main([]) == 0
    payload = json.loads(cfg.read_text(encoding="utf-8"))
    assert payload["enabled"] == ["firebase"]


def test_bootstrap_plugins_clones_mobsf_when_enabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    cfg = tmp_path / "plugins.json"
    tools = tmp_path / "tools"
    tools.mkdir()
    monkeypatch.setenv("ENABLE_PLUGINS", "true")
    monkeypatch.setenv("ENABLE_MOBSF", "true")
    monkeypatch.setenv("PLUGINS_CONFIG", str(cfg))
    monkeypatch.setenv("TOOLS_ROOT", str(tools))

    cloned: dict[str, int] = {"clone": 0, "setup": 0}
    repo_dir = tools / "mobsf" / "Mobile-Security-Framework-MobSF"

    def fake_clone(_tools_root):
        repo_dir.mkdir(parents=True, exist_ok=True)
        (repo_dir / ".git").mkdir(exist_ok=True)
        cloned["clone"] += 1
        yield "[client] cloning"
        yield "[exit 0]"

    def fake_setup(_tools_root):
        cloned["setup"] += 1
        yield "[client] setup"
        yield "[exit 0]"

    def fake_repo_path(tools_root):
        return Path(tools_root) / "mobsf" / "Mobile-Security-Framework-MobSF"

    from apk_web.plugins.mobsf import github_installer

    monkeypatch.setattr(github_installer, "clone_stream", fake_clone)
    monkeypatch.setattr(github_installer, "setup_stream", fake_setup)
    monkeypatch.setattr(github_installer, "repo_path", fake_repo_path)

    from scripts import bootstrap_plugins

    assert bootstrap_plugins.main([]) == 0
    assert cloned == {"clone": 1, "setup": 0}, "should not run setup without --with-mobsf-setup"


def test_bootstrap_plugins_with_mobsf_setup_runs_setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    cfg = tmp_path / "plugins.json"
    tools = tmp_path / "tools"
    tools.mkdir()
    monkeypatch.setenv("ENABLE_PLUGINS", "true")
    monkeypatch.setenv("ENABLE_MOBSF", "true")
    monkeypatch.setenv("PLUGINS_CONFIG", str(cfg))
    monkeypatch.setenv("TOOLS_ROOT", str(tools))

    repo_dir = tools / "mobsf" / "Mobile-Security-Framework-MobSF"
    (repo_dir / ".git").mkdir(parents=True)  # pretend already cloned

    setup_ran: list[bool] = []

    def fake_clone(_tools_root):
        yield "[client] noop"
        yield "[exit 0]"

    def fake_setup(_tools_root):
        setup_ran.append(True)
        yield "[client] running setup"
        yield "[exit 0]"

    def fake_repo_path(tools_root):
        return Path(tools_root) / "mobsf" / "Mobile-Security-Framework-MobSF"

    from apk_web.plugins.mobsf import github_installer

    monkeypatch.setattr(github_installer, "clone_stream", fake_clone)
    monkeypatch.setattr(github_installer, "setup_stream", fake_setup)
    monkeypatch.setattr(github_installer, "repo_path", fake_repo_path)

    from scripts import bootstrap_plugins

    assert bootstrap_plugins.main(["--with-mobsf-setup"]) == 0
    assert setup_ran == [True]


def test_bootstrap_plugins_disabled_via_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    cfg = tmp_path / "plugins.json"
    monkeypatch.setenv("ENABLE_PLUGINS", "false")
    monkeypatch.setenv("PLUGINS_CONFIG", str(cfg))

    from scripts import bootstrap_plugins

    assert bootstrap_plugins.main([]) == 0
    assert not cfg.exists()


# ---------------------------------------------------------------------------
# bootstrap_plugin_deps
# ---------------------------------------------------------------------------


def test_bootstrap_plugin_deps_skips_when_all_present(monkeypatch: pytest.MonkeyPatch):
    """If every declared pip_requires import is available, no pip is invoked."""

    from scripts import bootstrap_plugin_deps

    fake_plugin = type(
        "P",
        (),
        {"pip_requires": ["flask", "click:click"], "id": "fake", "name": "Fake"},
    )()

    monkeypatch.setattr(bootstrap_plugin_deps, "_builtin_plugins", lambda: [fake_plugin])

    called: list[list[str]] = []
    monkeypatch.setattr(
        bootstrap_plugin_deps.subprocess,
        "call",
        lambda argv, *a, **k: called.append(argv) or 0,
    )
    assert bootstrap_plugin_deps.main() == 0
    assert called == [], "no install should be attempted when everything is already importable"


def test_bootstrap_plugin_deps_installs_missing(monkeypatch: pytest.MonkeyPatch):
    from scripts import bootstrap_plugin_deps

    fake_plugin = type(
        "P",
        (),
        {
            "pip_requires": ["totally-not-real-pkg:nonexistent_xyz"],
            "id": "fake",
            "name": "Fake",
        },
    )()

    monkeypatch.setattr(bootstrap_plugin_deps, "_builtin_plugins", lambda: [fake_plugin])

    called: list[list[str]] = []
    monkeypatch.setattr(
        bootstrap_plugin_deps.subprocess,
        "call",
        lambda argv, *a, **k: called.append(argv) or 0,
    )

    assert bootstrap_plugin_deps.main() == 0
    assert called, "should have called pip install"
    argv = called[0]
    assert argv[1:4] == ["-m", "pip", "install"]
    assert "totally-not-real-pkg" in argv


# ---------------------------------------------------------------------------
# write_run_bat
# ---------------------------------------------------------------------------


def test_run_bat_references_apkwooper_venv():
    text = (REPO_ROOT / "run.bat").read_text(encoding="utf-8")
    assert ".apkwooper\\Scripts\\python.exe" in text
    assert "python -m apk_web" not in text  # uses VENV_PY explicitly
    assert "-m apk_web" in text


def test_run_bat_warns_when_venv_missing():
    text = (REPO_ROOT / "run.bat").read_text(encoding="utf-8")
    assert "Virtual environment not found" in text
    assert "build.bat" in text


def test_run_bat_warns_when_env_missing():
    text = (REPO_ROOT / "run.bat").read_text(encoding="utf-8")
    assert ".env not found" in text


def test_write_run_bat_rewrites_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from scripts import write_run_bat

    target = tmp_path / "run.bat"
    monkeypatch.setattr(write_run_bat, "TARGET", target)
    assert write_run_bat.main() == 0
    body = target.read_text(encoding="utf-8")
    assert "apkwooper" in body
    assert "-m apk_web" in body


# ---------------------------------------------------------------------------
# build.ps1 contents
# ---------------------------------------------------------------------------


def test_build_ps1_enforces_python_312():
    text = (REPO_ROOT / "build.ps1").read_text(encoding="utf-8")
    assert "3.12" in text
    assert ".apkwooper" in text
    assert "py -3.12" in text or "Resolve-Python312" in text


def test_build_ps1_invokes_helpers():
    text = (REPO_ROOT / "build.ps1").read_text(encoding="utf-8")
    for helper in (
        "init_env.py",
        "bootstrap_all_tools.py",
        "bootstrap_plugins.py",
        "bootstrap_plugin_deps.py",
        "write_run_bat.py",
    ):
        assert helper in text, f"build.ps1 should invoke {helper}"


def test_build_ps1_auto_installs_python_when_missing():
    """When Python 3.12 is not on PATH, build.ps1 should bootstrap it.

    We don't run the script here; we just assert the install paths are wired:
      * official python.org installer download URL,
      * per-user silent install args (no admin),
      * a -NoAutoInstallPython escape hatch for CI.
    """
    text = (REPO_ROOT / "build.ps1").read_text(encoding="utf-8")
    assert "python.org/ftp/python" in text
    assert "InstallAllUsers=0" in text, "must request per-user (no admin) install"
    assert "/quiet" in text, "installer must run silently"
    assert "NoAutoInstallPython" in text, "should expose an opt-out flag"
    assert "Install-Python312" in text
    assert "winget" in text, "should try winget before falling back to direct download"
