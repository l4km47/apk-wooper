"""Tiny end-to-end run of the analysis engine over a synthetic workspace."""

from __future__ import annotations

from pathlib import Path

from apk_web.analysis.engine import EngineConfig, run_engine
from apk_web.analysis.store import AnalysisStore


JAVA_SOURCE = """
public class Api {
  static String FIREBASE = "AIzaSyAbcDefGhIjKlMnOpQrStUvWxYz0123456";
  static String OPENAI = "sk-abcdefghijklmnopqrstuvwxyz123456";
  static String URL = "https://api.example.com/v1";
  static String AWS = "AKIAIOSFODNN7EXAMPLE";
  static String LOOPBACK = "127.0.0.1";
  static String SCHEMA = "http://schemas.android.com/apk/res/android";
  void f() { new Retrofit.Builder().baseUrl("https://prod.example.com/v2/").build(); }
}
"""

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.demo">
  <uses-permission android:name="android.permission.READ_SMS"/>
  <application
      android:debuggable="true"
      android:allowBackup="true"
      android:usesCleartextTraffic="true">
    <activity android:name=".Public" android:exported="true">
      <intent-filter>
        <data android:scheme="demoapp" android:host="open"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

STRINGS_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
  <string name="google_api_key">AIzaSyExampleResourceKey0000000000000000</string>
  <string name="firebase_database_url">https://demo-12345.firebaseio.com</string>
</resources>
"""


def _build_workspace(root: Path) -> None:
    out = root / "out"
    sources = out / "jadx" / "sources" / "com" / "demo"
    sources.mkdir(parents=True)
    (sources / "Api.java").write_text(JAVA_SOURCE, encoding="utf-8")

    apktool = out / "apktool"
    apktool.mkdir(parents=True)
    (apktool / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (apktool / "res" / "values").mkdir(parents=True)
    (apktool / "res" / "values" / "strings.xml").write_text(STRINGS_XML, encoding="utf-8")


def test_engine_writes_findings_and_summary(tmp_path: Path) -> None:
    root = tmp_path / "job1"
    _build_workspace(root)

    store = AnalysisStore(root)
    result = run_engine(
        job_root=root,
        scan_root=root / "out",
        store=store,
        config=EngineConfig(workers=2),
    )

    assert result.findings_count > 0
    assert store.findings_path.is_file()
    assert store.summary_path.is_file()

    findings = store.read_findings()
    rule_ids = {f["rule_id"] for f in findings}
    assert "secret.firebase_api_key" in rule_ids
    assert "secret.openai" in rule_ids
    assert "secret.aws_access_key" in rule_ids
    assert "manifest.debuggable" in rule_ids
    assert "manifest.dangerous_permission" in rule_ids
    assert "manifest.deeplink_scheme" in rule_ids
    assert "net.retrofit_baseurl" in rule_ids

    # Loopback IPv4 + schemas.android.com URL should be filtered out as noise.
    matches = [f["match"] for f in findings if f["category"] == "network"]
    assert not any("127.0.0.1" in m for m in matches)
    assert not any("schemas.android.com" in m for m in matches)

    summary = store.read_summary()
    assert summary["findings_count"] == len(findings)
    assert summary["by_severity"].get("high", 0) >= 1
    assert summary["files_scanned"] >= 1


def test_secret_match_is_redacted(tmp_path: Path) -> None:
    root = tmp_path / "job1"
    _build_workspace(root)
    store = AnalysisStore(root)
    run_engine(
        job_root=root,
        scan_root=root / "out",
        store=store,
        config=EngineConfig(workers=2),
    )
    findings = store.read_findings()
    firebase = next(f for f in findings if f["rule_id"] == "secret.firebase_api_key")
    assert "AIzaSyAbcDefGhIjKlMnOpQrStUvWxYz0123456" not in firebase["match"]
    assert firebase["full_match"].startswith("AIza")
