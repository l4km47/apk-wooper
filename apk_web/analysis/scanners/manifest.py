from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, List, Optional

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.scanners.base import Scanner


ANDROID_NS = "http://schemas.android.com/apk/res/android"
_NS = {"a": ANDROID_NS}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

DANGEROUS_PERMISSIONS = frozenset(
    {
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    }
)

STANDARD_SCHEMES = frozenset({"http", "https", "file", "content", "android-app", "market"})


def _attr(elem: ET.Element, name: str) -> Optional[str]:
    return elem.get(f"{{{ANDROID_NS}}}{name}")


def _bool_attr(elem: ET.Element, name: str) -> bool:
    val = _attr(elem, name)
    return (val or "").lower() == "true"


def _find_manifest(scan_root: Path) -> Optional[Path]:
    # Apktool writes the decoded text manifest to ``out/apktool/AndroidManifest.xml``
    # (the JADX output also contains it but unpredictably). Prefer apktool's copy.
    candidates = [
        scan_root / "apktool" / "AndroidManifest.xml",
        scan_root / "AndroidManifest.xml",
        scan_root / "jadx" / "resources" / "AndroidManifest.xml",
        scan_root / "jadx" / "AndroidManifest.xml",
    ]
    for p in candidates:
        if p.is_file():
            return p
    for p in scan_root.rglob("AndroidManifest.xml"):
        return p
    return None


class _ManifestScanner:
    name = "manifest"
    kind = "global"

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        return ()

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        scan_root = job_root / "out"
        if not scan_root.is_dir():
            scan_root = job_root
        manifest = _find_manifest(scan_root)
        if manifest is None:
            return ()
        try:
            tree = ET.parse(str(manifest))
        except (ET.ParseError, OSError):
            return ()
        rel_path = manifest.resolve().relative_to(job_root.resolve()).as_posix()
        root = tree.getroot()
        out: List[Finding] = []

        application = root.find("application")
        if application is not None:
            if _bool_attr(application, "debuggable"):
                out.append(
                    make_finding(
                        rule_id="manifest.debuggable",
                        category=Category.MANIFEST,
                        severity=Severity.HIGH,
                        title="application android:debuggable=\"true\"",
                        file=rel_path,
                        full_match='android:debuggable="true"',
                        tool="manifest",
                        confidence=0.99,
                        redact=False,
                    )
                )
            backup = _attr(application, "allowBackup")
            if backup is None or backup.lower() == "true":
                out.append(
                    make_finding(
                        rule_id="manifest.allow_backup",
                        category=Category.MANIFEST,
                        severity=Severity.LOW,
                        title="android:allowBackup not disabled",
                        file=rel_path,
                        full_match=f'android:allowBackup="{backup or "default-true"}"',
                        tool="manifest",
                        confidence=0.85,
                        redact=False,
                    )
                )
            if _bool_attr(application, "usesCleartextTraffic"):
                out.append(
                    make_finding(
                        rule_id="manifest.cleartext_traffic",
                        category=Category.MANIFEST,
                        severity=Severity.MEDIUM,
                        title="android:usesCleartextTraffic=\"true\"",
                        file=rel_path,
                        full_match='android:usesCleartextTraffic="true"',
                        tool="manifest",
                        confidence=0.95,
                        redact=False,
                    )
                )
            nsc = _attr(application, "networkSecurityConfig")
            if nsc:
                out.append(
                    make_finding(
                        rule_id="manifest.network_security_config",
                        category=Category.MANIFEST,
                        severity=Severity.INFO,
                        title="Custom networkSecurityConfig",
                        file=rel_path,
                        full_match=f'android:networkSecurityConfig="{nsc}"',
                        tool="manifest",
                        confidence=0.9,
                        redact=False,
                        extra={"ref": nsc},
                    )
                )

            for tag in COMPONENT_TAGS:
                for comp in application.iter(tag):
                    self._emit_component(comp, tag, rel_path, out)

        for perm in root.iter("uses-permission"):
            pname = _attr(perm, "name") or ""
            if pname in DANGEROUS_PERMISSIONS:
                out.append(
                    make_finding(
                        rule_id="manifest.dangerous_permission",
                        category=Category.MANIFEST,
                        severity=Severity.LOW,
                        title=f"Dangerous permission: {pname}",
                        file=rel_path,
                        full_match=pname,
                        tool="manifest",
                        confidence=0.99,
                        redact=False,
                    )
                )

        for cperm in root.iter("permission"):
            pname = _attr(cperm, "name") or ""
            protection = _attr(cperm, "protectionLevel") or "normal"
            if "signature" not in protection.lower():
                out.append(
                    make_finding(
                        rule_id="manifest.custom_permission",
                        category=Category.MANIFEST,
                        severity=Severity.LOW,
                        title=f"Custom permission with weak protection: {pname}",
                        file=rel_path,
                        full_match=f"{pname} protectionLevel={protection}",
                        tool="manifest",
                        confidence=0.7,
                        redact=False,
                        extra={"name": pname, "protectionLevel": protection},
                    )
                )

        return out

    def _emit_component(
        self,
        comp: ET.Element,
        tag: str,
        rel_path: str,
        out: List[Finding],
    ) -> None:
        name = _attr(comp, "name") or "(unnamed)"
        exported_attr = _attr(comp, "exported")
        has_filter = comp.find("intent-filter") is not None

        # Pre-API26 default: exported=true when intent-filter is present.
        exported = (
            exported_attr.lower() == "true"
            if exported_attr is not None
            else has_filter
        )
        permission = _attr(comp, "permission")
        if exported and not permission:
            out.append(
                make_finding(
                    rule_id="manifest.exported_component",
                    category=Category.MANIFEST,
                    severity=Severity.MEDIUM,
                    title=f"Exported <{tag}> without permission: {name}",
                    file=rel_path,
                    full_match=f"<{tag} android:name=\"{name}\" exported=\"true\">",
                    tool="manifest",
                    confidence=0.9,
                    redact=False,
                    extra={"component": tag, "name": name},
                )
            )

        for ifilter in comp.findall("intent-filter"):
            for data in ifilter.findall("data"):
                scheme = _attr(data, "scheme")
                host = _attr(data, "host")
                if scheme and scheme not in STANDARD_SCHEMES:
                    out.append(
                        make_finding(
                            rule_id="manifest.deeplink_scheme",
                            category=Category.MANIFEST,
                            severity=Severity.LOW,
                            title=f"Deeplink scheme '{scheme}' on {tag} {name}",
                            file=rel_path,
                            full_match=f"{scheme}://{host or ''}",
                            tool="manifest",
                            confidence=0.95,
                            redact=False,
                            extra={"scheme": scheme, "host": host, "component": name},
                        )
                    )


SCANNER: Scanner = _ManifestScanner()
