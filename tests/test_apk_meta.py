"""Tests for :mod:`apk_web.apk_meta`."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from apk_web import apk_meta


MANIFEST_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          android:compileSdkVersion="34"
          android:versionCode="42"
          android:versionName="1.2.3"
          package="com.example.app">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:icon="@mipmap/ic_launcher"
               android:label="@string/app_name"
               android:debuggable="true">
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

STRINGS_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
  <string name="app_name">My Cool App</string>
  <string name="other">Nope</string>
</resources>
"""


def _make_png(path: Path) -> None:
    """Write a 1x1 valid PNG so the icon copy code accepts it."""
    png = bytes.fromhex(
        "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4"
        "890000000A49444154789C6300010000000500010D0A2DB40000000049454E44"
        "AE426082"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def _make_job(tmp_path: Path, *, manifest: str = MANIFEST_TEMPLATE,
              strings: str = STRINGS_XML, with_icon: bool = True,
              with_apk: bool = True) -> Path:
    job = tmp_path / "job1"
    apktool = job / "out" / "apktool"
    apktool.mkdir(parents=True)
    (apktool / "AndroidManifest.xml").write_text(manifest, encoding="utf-8")
    (apktool / "res" / "values").mkdir(parents=True)
    (apktool / "res" / "values" / "strings.xml").write_text(strings, encoding="utf-8")
    if with_icon:
        _make_png(apktool / "res" / "mipmap-mdpi" / "ic_launcher.png")
        _make_png(apktool / "res" / "mipmap-xxxhdpi" / "ic_launcher.png")
    if with_apk:
        apk = job / "input.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", "binary-axml-stub")
            zf.writestr("classes.dex", b"\x00\x01\x02")
    return job


def test_extract_full_metadata(tmp_path: Path):
    job = _make_job(tmp_path)
    meta = apk_meta.extract(job)
    assert meta.package == "com.example.app"
    assert meta.label == "My Cool App"
    assert meta.version_name == "1.2.3"
    assert meta.version_code == 42
    assert meta.min_sdk == 21
    assert meta.target_sdk == 33
    assert meta.compile_sdk == 34
    assert meta.main_activity == "com.example.app.MainActivity"
    assert meta.is_debuggable is True
    assert "android.permission.INTERNET" in meta.permissions
    assert "android.permission.CAMERA" in meta.permissions
    assert meta.size_bytes is not None and meta.size_bytes > 0
    assert "md5" in meta.hashes and len(meta.hashes["md5"]) == 32
    assert "sha1" in meta.hashes and len(meta.hashes["sha1"]) == 40
    assert "sha256" in meta.hashes and len(meta.hashes["sha256"]) == 64


def test_icon_materialized_under_meta(tmp_path: Path):
    job = _make_job(tmp_path)
    meta = apk_meta.extract(job)
    assert meta.icon_rel.startswith("meta/icon")
    materialized = job / meta.icon_rel
    assert materialized.is_file()
    # Should prefer the xxxhdpi variant.
    src_high = job / "out" / "apktool" / "res" / "mipmap-xxxhdpi" / "ic_launcher.png"
    assert materialized.read_bytes() == src_high.read_bytes()


def test_extract_handles_missing_apk(tmp_path: Path):
    job = _make_job(tmp_path, with_apk=False)
    meta = apk_meta.extract(job)
    assert meta.package == "com.example.app"
    assert meta.hashes == {}
    assert meta.size_bytes is None


def test_extract_handles_missing_manifest(tmp_path: Path):
    job = tmp_path / "job"
    (job / "out" / "apktool").mkdir(parents=True)
    # No manifest, no apk.
    meta = apk_meta.extract(job)
    assert meta.package == ""
    assert meta.label == ""
    assert meta.version_name == ""


def test_extract_resolves_literal_label(tmp_path: Path):
    manifest = MANIFEST_TEMPLATE.replace(
        'android:label="@string/app_name"',
        'android:label="Plain Label"',
    )
    job = _make_job(tmp_path, manifest=manifest)
    meta = apk_meta.extract(job)
    assert meta.label == "Plain Label"


def test_extract_unresolvable_string_falls_back_to_reference(tmp_path: Path):
    strings = STRINGS_XML.replace("My Cool App", "Renamed")
    strings = strings.replace('name="app_name"', 'name="other_name"')
    job = _make_job(tmp_path, strings=strings)
    meta = apk_meta.extract(job)
    # No app_name resource — should fall back to the raw reference.
    assert meta.label == "@string/app_name"


def test_extract_hashes_match_apk_contents(tmp_path: Path):
    job = _make_job(tmp_path)
    apk_bytes = (job / "input.apk").read_bytes()
    meta = apk_meta.extract(job)
    assert meta.hashes["md5"] == hashlib.md5(apk_bytes).hexdigest()
    assert meta.hashes["sha1"] == hashlib.sha1(apk_bytes).hexdigest()
    assert meta.hashes["sha256"] == hashlib.sha256(apk_bytes).hexdigest()


def test_apktool_yml_fallback_for_sdk(tmp_path: Path):
    # Manifest without uses-sdk, apktool.yml supplies the values.
    manifest = MANIFEST_TEMPLATE.replace(
        '  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>\n',
        "",
    )
    job = _make_job(tmp_path, manifest=manifest)
    (job / "out" / "apktool" / "apktool.yml").write_text(
        "!!brut.androlib.meta.MetaInfo\n"
        "version: 2.11.1\n"
        "sdkInfo:\n"
        "  minSdkVersion: '21'\n"
        "  targetSdkVersion: '33'\n",
        encoding="utf-8",
    )
    meta = apk_meta.extract(job)
    assert meta.min_sdk == 21
    assert meta.target_sdk == 33
    assert meta.apktool_version == "2.11.1"


def test_to_dict_round_trips_dataclass(tmp_path: Path):
    job = _make_job(tmp_path)
    meta = apk_meta.extract(job)
    payload = meta.to_dict()
    assert payload["package"] == meta.package
    assert payload["hashes"]["sha256"] == meta.hashes["sha256"]
    assert payload["permissions"] == meta.permissions
    # The dict must be JSON-serializable (no Path objects etc.)
    import json
    json.dumps(payload)


def test_dotted_main_activity_resolution(tmp_path: Path):
    manifest = MANIFEST_TEMPLATE.replace(
        'android:name=".MainActivity"',
        'android:name="MainActivity"',
    )
    job = _make_job(tmp_path, manifest=manifest)
    meta = apk_meta.extract(job)
    assert meta.main_activity == "com.example.app.MainActivity"
