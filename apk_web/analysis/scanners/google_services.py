from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.scanners.base import Scanner


# Strings in res/values/strings.xml that Google services often inject when
# google-services.json is processed by the gradle plugin.
GOOGLE_STRING_KEYS = {
    "google_api_key": ("secret.firebase_api_key", "Firebase/Google API key", Severity.HIGH, True),
    "google_crash_reporting_api_key": (
        "secret.firebase_api_key",
        "Firebase Crash Reporting API key",
        Severity.HIGH,
        True,
    ),
    "google_app_id": ("sdk.firebase_app_id", "Firebase App ID", Severity.LOW, False),
    "firebase_database_url": (
        "secret.firebase_url",
        "Firebase Realtime Database URL",
        Severity.MEDIUM,
        False,
    ),
    "gcm_defaultSenderId": ("sdk.gcm_sender_id", "GCM default sender ID", Severity.LOW, False),
    "default_web_client_id": (
        "secret.google_oauth_client_id",
        "Default web OAuth client ID",
        Severity.MEDIUM,
        False,
    ),
    "project_id": ("sdk.firebase_project_id", "Firebase project ID", Severity.INFO, False),
    "google_storage_bucket": ("sdk.firebase_storage_bucket", "Firebase storage bucket", Severity.INFO, False),
}


def _iter_string_xml_files(scan_root: Path) -> Iterable[Path]:
    candidates = [
        scan_root / "apktool" / "res" / "values" / "strings.xml",
    ]
    for p in candidates:
        if p.is_file():
            yield p
    for p in (scan_root / "apktool" / "res").rglob("strings.xml") if (scan_root / "apktool" / "res").is_dir() else []:
        yield p


def _iter_google_services_json(scan_root: Path) -> Iterable[Path]:
    if not scan_root.is_dir():
        return
    for p in scan_root.rglob("google-services.json"):
        yield p


class _GoogleServicesScanner:
    name = "google_services"
    kind = "global"

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        return ()

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        scan_root = job_root / "out"
        if not scan_root.is_dir():
            scan_root = job_root
        out: List[Finding] = []
        seen: set[tuple[str, str]] = set()

        for xml_path in _iter_string_xml_files(scan_root):
            try:
                tree = ET.parse(str(xml_path))
            except (ET.ParseError, OSError):
                continue
            rel = xml_path.resolve().relative_to(job_root.resolve()).as_posix()
            root = tree.getroot()
            for elem in root.iter("string"):
                name = (elem.get("name") or "").strip()
                if name not in GOOGLE_STRING_KEYS:
                    continue
                value = (elem.text or "").strip()
                if not value:
                    continue
                rule_id, title, severity, redact = GOOGLE_STRING_KEYS[name]
                key = (rule_id, value)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    make_finding(
                        rule_id=rule_id,
                        category=Category.SECRET if rule_id.startswith("secret.") else Category.SDK,
                        severity=severity,
                        title=f"{title} ({name})",
                        file=rel,
                        full_match=value,
                        tool="google_services",
                        confidence=0.97,
                        redact=redact,
                        extra={"name": name},
                    )
                )

        for js_path in _iter_google_services_json(scan_root):
            try:
                data = json.loads(js_path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            rel = js_path.resolve().relative_to(job_root.resolve()).as_posix()
            project_info = data.get("project_info") or {}
            project_id = project_info.get("project_id")
            if project_id:
                out.append(
                    make_finding(
                        rule_id="sdk.firebase_project_id",
                        category=Category.SDK,
                        severity=Severity.INFO,
                        title=f"Firebase project: {project_id}",
                        file=rel,
                        full_match=project_id,
                        tool="google_services",
                        confidence=1.0,
                        redact=False,
                    )
                )
            for client in data.get("client", []) or []:
                for api_key in client.get("api_key", []) or []:
                    val = api_key.get("current_key")
                    if not val:
                        continue
                    key = ("secret.firebase_api_key", val)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(
                        make_finding(
                            rule_id="secret.firebase_api_key",
                            category=Category.SECRET,
                            severity=Severity.HIGH,
                            title="Firebase/Google API key (from google-services.json)",
                            file=rel,
                            full_match=val,
                            tool="google_services",
                            confidence=1.0,
                            redact=True,
                        )
                    )
                client_info = client.get("client_info") or {}
                app_id = client_info.get("mobilesdk_app_id")
                if app_id:
                    out.append(
                        make_finding(
                            rule_id="sdk.firebase_app_id",
                            category=Category.SDK,
                            severity=Severity.LOW,
                            title="Firebase mobile SDK app ID",
                            file=rel,
                            full_match=app_id,
                            tool="google_services",
                            confidence=1.0,
                            redact=False,
                        )
                    )
                for oauth in client.get("oauth_client", []) or []:
                    cid = oauth.get("client_id")
                    if not cid:
                        continue
                    key = ("secret.google_oauth_client_id", cid)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(
                        make_finding(
                            rule_id="secret.google_oauth_client_id",
                            category=Category.SECRET,
                            severity=Severity.MEDIUM,
                            title="Google OAuth client ID (from google-services.json)",
                            file=rel,
                            full_match=cid,
                            tool="google_services",
                            confidence=1.0,
                            redact=False,
                        )
                    )
        return out


SCANNER: Scanner = _GoogleServicesScanner()
