"""Tests for the optional APKiD scanner."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from apk_web.analysis.models import Category, Severity
from apk_web.analysis.scanners import apkid as apkid_mod


@pytest.fixture
def fake_apk(tmp_path: Path) -> Path:
    job_root = tmp_path / "job"
    job_root.mkdir()
    apk = job_root / "input.apk"
    # The scanner does not parse the APK itself when both backends are
    # monkeypatched, so a tiny placeholder file is enough.
    apk.write_bytes(b"PK\x03\x04fake-apk-bytes")
    return apk


def _sample_results() -> Dict[str, Any]:
    return {
        "apkid_version": "test",
        "files": [
            {
                "filename": "input.apk",
                "matches": {
                    "packer": ["AppSealing"],
                    "obfuscator": ["ProGuard"],
                    "anti_vm": ["check_for_Genymotion"],
                    "anti_debug": ["ptrace"],
                    "compiler": ["dexlib 2.x"],
                },
            },
            {
                "filename": "input.apk!classes.dex",
                "matches": {"compiler": ["dx (Android SDK build-tools)"]},
            },
        ],
    }


def test_findings_from_results_maps_categories(fake_apk: Path, monkeypatch):
    monkeypatch.setattr(apkid_mod, "_scan_via_python", lambda _apk: _sample_results())
    # Should not be reached when the python backend returns a value.
    monkeypatch.setattr(
        apkid_mod,
        "_scan_via_subprocess",
        lambda _apk: pytest.fail("subprocess fallback was used unexpectedly"),
    )

    scanner = apkid_mod.ApkidScanner()
    findings = list(scanner.scan_global(job_root=fake_apk.parent))

    by_rule = {f.rule_id: f for f in findings}

    packer = by_rule["apkid.packer.appsealing"]
    assert packer.severity == Severity.HIGH
    assert packer.category == Category.PROTECTION
    assert packer.file == "input.apk"
    assert packer.tool == "apkid"
    assert "Packer detected" in packer.title

    obf = by_rule["apkid.obfuscator.proguard"]
    assert obf.severity == Severity.MEDIUM
    assert obf.category == Category.PROTECTION

    anti_vm = by_rule["apkid.anti_vm.check_for_genymotion"]
    assert anti_vm.severity == Severity.HIGH
    assert anti_vm.category == Category.PROTECTION

    anti_debug = by_rule["apkid.anti_debug.ptrace"]
    assert anti_debug.severity == Severity.HIGH
    assert anti_debug.category == Category.PROTECTION

    compiler = by_rule["apkid.compiler.dexlib_2_x"]
    assert compiler.severity == Severity.INFO
    assert compiler.category == Category.SDK

    inner = by_rule["apkid.compiler.dx_android_sdk_build_tools"]
    assert inner.extra.get("inner_entry") == "classes.dex"
    assert "classes.dex" in inner.snippet


def test_subprocess_fallback_used_when_python_returns_none(fake_apk: Path, monkeypatch):
    monkeypatch.setattr(apkid_mod, "_scan_via_python", lambda _apk: None)
    monkeypatch.setattr(
        apkid_mod, "_scan_via_subprocess", lambda _apk: _sample_results()
    )

    scanner = apkid_mod.ApkidScanner()
    findings = list(scanner.scan_global(job_root=fake_apk.parent))
    assert any(f.rule_id.startswith("apkid.packer.") for f in findings)


def test_no_op_when_both_backends_unavailable(fake_apk: Path, monkeypatch):
    monkeypatch.setattr(apkid_mod, "_scan_via_python", lambda _apk: None)
    monkeypatch.setattr(apkid_mod, "_scan_via_subprocess", lambda _apk: None)

    scanner = apkid_mod.ApkidScanner()
    findings = list(scanner.scan_global(job_root=fake_apk.parent))
    assert findings == []


def test_skips_when_input_apk_missing(tmp_path: Path):
    scanner = apkid_mod.ApkidScanner()
    findings = list(scanner.scan_global(job_root=tmp_path))
    assert findings == []


def test_coerce_json_handles_prefix_noise():
    payload = json.dumps({"files": []})
    decorated = "WARNING: yara something\n" + payload
    assert apkid_mod._coerce_json(decorated) == {"files": []}
    assert apkid_mod._coerce_json("") is None
    assert apkid_mod._coerce_json("no json here") is None


def test_runner_skips_apkid_when_package_missing(monkeypatch):
    """``_resolve_scanners`` should not append ApkidScanner when apkid is
    not importable, even with ENABLE_APKID=1."""
    from apk_web.analysis import runner as runner_mod
    from apk_web.analysis.scanners.apkid import ApkidScanner

    class _FakeApp:
        config: Dict[str, Any] = {
            "ENABLE_APKID": True,
            "ENABLE_GITLEAKS": False,
            "ENABLE_TRUFFLEHOG": False,
            "ENABLE_RADARE2": False,
            "TOOLS_ROOT": "tools",
        }

    monkeypatch.setattr(runner_mod.importlib.util, "find_spec", lambda _n: None)
    scanners = runner_mod._resolve_scanners(_FakeApp())
    assert not any(isinstance(s, ApkidScanner) for s in scanners)


def test_runner_appends_apkid_when_package_present(monkeypatch):
    from apk_web.analysis import runner as runner_mod
    from apk_web.analysis.scanners.apkid import ApkidScanner

    class _FakeApp:
        config: Dict[str, Any] = {
            "ENABLE_APKID": True,
            "ENABLE_GITLEAKS": False,
            "ENABLE_TRUFFLEHOG": False,
            "ENABLE_RADARE2": False,
            "TOOLS_ROOT": "tools",
        }

    monkeypatch.setattr(
        runner_mod.importlib.util, "find_spec", lambda _n: object()
    )
    scanners = runner_mod._resolve_scanners(_FakeApp())
    assert any(isinstance(s, ApkidScanner) for s in scanners)
