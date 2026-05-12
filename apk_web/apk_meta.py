"""APK metadata extraction.

Pulls human-readable info out of a job directory after decompile so the
dashboard can show app name, icon, version, SDK levels, hashes, etc.

We try to keep this dependency-free: parse the apktool-decoded
``AndroidManifest.xml`` (text form), resolve resource references against
``res/values/strings.xml``, pick the highest-density launcher icon, and
hash ``input.apk`` for fingerprints.

Robustness rules:

* Every public function tolerates partially missing inputs and never
  raises. Missing fields end up as ``None`` / empty strings so the
  dashboard can render whatever is available.
* We never require apktool's optional ``apktool.yml`` (recent versions
  sometimes omit it) but we read it when present.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOG = logging.getLogger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Densities in upscale order; we prefer higher densities for the icon.
_DENSITY_PREFERENCE = (
    "xxxhdpi",
    "xxhdpi",
    "xhdpi",
    "hdpi",
    "tvdpi",
    "mdpi",
    "ldpi",
    "anydpi-v26",
    "anydpi",
    "nodpi",
)

# Image extensions we are willing to copy as the icon. WEBP / PNG are
# universally browser-friendly; XML icons (vector / adaptive) are skipped
# here because they would need rendering.
_ICON_EXTS = (".webp", ".png", ".jpg", ".jpeg", ".gif")

# Filenames inside the job dir that we materialize for the dashboard.
ICON_REL = "meta/icon"  # extension is appended dynamically


@dataclass
class ApkMeta:
    package: str = ""
    label: str = ""
    version_name: str = ""
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    main_activity: str = ""
    permissions: List[str] = field(default_factory=list)
    icon_rel: str = ""
    icon_resource: str = ""
    size_bytes: Optional[int] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    apktool_version: str = ""
    is_debuggable: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "label": self.label,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "compile_sdk": self.compile_sdk,
            "main_activity": self.main_activity,
            "permissions": list(self.permissions),
            "icon_rel": self.icon_rel,
            "icon_resource": self.icon_resource,
            "size_bytes": self.size_bytes,
            "hashes": dict(self.hashes),
            "apktool_version": self.apktool_version,
            "is_debuggable": self.is_debuggable,
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def extract(job_dir: Path) -> ApkMeta:
    """Return an :class:`ApkMeta` for the given job directory.

    Always returns a value; on partial / missing data, only the fields
    we could resolve are populated.
    """
    job_dir = Path(job_dir)
    meta = ApkMeta()

    apk = job_dir / "input.apk"
    if apk.is_file():
        try:
            meta.size_bytes = apk.stat().st_size
        except OSError:
            pass
        meta.hashes = _hash_file(apk)

    apktool_root = job_dir / "out" / "apktool"
    manifest_path = apktool_root / "AndroidManifest.xml"
    if manifest_path.is_file():
        _populate_from_manifest(meta, manifest_path, apktool_root)
    elif apk.is_file():
        # Without apktool output we can still confirm it's a valid APK by
        # checking the central directory; per-package introspection (binary
        # AXML parsing) is intentionally out of scope.
        try:
            with zipfile.ZipFile(apk) as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    # Mark it as recognized but no further info.
                    pass
        except (zipfile.BadZipFile, OSError):
            pass

    # apktool.yml -- newer apktool versions sometimes omit it; read what is
    # available without failing.
    yml = apktool_root / "apktool.yml"
    if yml.is_file():
        _read_apktool_yml(meta, yml)

    if meta.icon_resource:
        copied = _materialize_icon(meta.icon_resource, apktool_root, job_dir)
        if copied:
            meta.icon_rel = copied

    return meta


def write_to_meta(meta: ApkMeta, job_meta: Dict[str, Any]) -> Dict[str, Any]:
    """Merge an :class:`ApkMeta` into a JobStore meta dict in-place."""
    job_meta["apk_meta"] = meta.to_dict()
    return job_meta


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def _hash_file(path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except OSError as exc:
        _LOG.warning("apk_meta: hashing %s failed: %s", path, exc)
        return {}
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------


def _qname(name: str) -> str:
    return f"{{{ANDROID_NS}}}{name}"


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _populate_from_manifest(meta: ApkMeta, manifest: Path, apktool_root: Path) -> None:
    try:
        tree = ET.parse(manifest)
    except (ET.ParseError, OSError) as exc:
        _LOG.warning("apk_meta: cannot parse manifest %s: %s", manifest, exc)
        return
    root = tree.getroot()
    if root is None:
        return

    meta.package = root.attrib.get("package", "") or ""

    meta.compile_sdk = _to_int(root.attrib.get(_qname("compileSdkVersion")))
    meta.version_name = root.attrib.get(_qname("versionName"), "") or ""
    meta.version_code = _to_int(root.attrib.get(_qname("versionCode")))

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        meta.min_sdk = _to_int(uses_sdk.attrib.get(_qname("minSdkVersion")))
        meta.target_sdk = _to_int(uses_sdk.attrib.get(_qname("targetSdkVersion")))

    perms: List[str] = []
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for el in root.findall(tag):
            name = el.attrib.get(_qname("name"))
            if name and name not in perms:
                perms.append(name)
    meta.permissions = perms

    application = root.find("application")
    if application is not None:
        debuggable = application.attrib.get(_qname("debuggable"))
        if debuggable is not None:
            meta.is_debuggable = debuggable.strip().lower() in {"true", "1"}

        meta.icon_resource = application.attrib.get(_qname("icon"), "") or ""
        raw_label = application.attrib.get(_qname("label"), "") or ""
        meta.label = _resolve_string_resource(raw_label, apktool_root)

        for activity in application.findall("activity"):
            intents = activity.findall("intent-filter")
            if not intents:
                continue
            launcher = False
            main = False
            for f in intents:
                for action in f.findall("action"):
                    if action.attrib.get(_qname("name")) == "android.intent.action.MAIN":
                        main = True
                for cat in f.findall("category"):
                    if cat.attrib.get(_qname("name")) == "android.intent.category.LAUNCHER":
                        launcher = True
            if main and launcher:
                act_name = activity.attrib.get(_qname("name"), "")
                if act_name:
                    if act_name.startswith(".") and meta.package:
                        act_name = meta.package + act_name
                    elif "." not in act_name and meta.package:
                        act_name = f"{meta.package}.{act_name}"
                    meta.main_activity = act_name
                break


_RES_REF_RE = re.compile(r"^@(?:[\w.]+:)?(?P<type>[\w]+)/(?P<name>[\w.]+)$")


def _resolve_string_resource(value: str, apktool_root: Path) -> str:
    """If ``value`` is ``@string/foo``, look up the value in ``res/values/strings.xml``."""
    if not value:
        return ""
    m = _RES_REF_RE.match(value.strip())
    if not m:
        return value
    if m.group("type") != "string":
        return value
    name = m.group("name")
    candidates = [
        apktool_root / "res" / "values" / "strings.xml",
        apktool_root / "res" / "values-en" / "strings.xml",
    ]
    for cand in candidates:
        if not cand.is_file():
            continue
        try:
            tree = ET.parse(cand)
        except (ET.ParseError, OSError):
            continue
        for el in tree.getroot().findall("string"):
            if el.attrib.get("name") == name:
                return (el.text or "").strip()
    return value


# ---------------------------------------------------------------------------
# Icon resolution
# ---------------------------------------------------------------------------


def _materialize_icon(icon_resource: str, apktool_root: Path, job_dir: Path) -> str:
    """Copy the best icon variant into ``job_dir/meta/icon.<ext>``.

    Returns the relative path inside the job dir (forward-slashes) or ""
    when no usable icon could be located.
    """
    m = _RES_REF_RE.match(icon_resource.strip())
    if not m:
        return ""
    res_type = m.group("type")  # "mipmap" or "drawable"
    res_name = m.group("name")
    if res_type not in ("mipmap", "drawable"):
        return ""

    res_root = apktool_root / "res"
    if not res_root.is_dir():
        return ""

    variants: List[Path] = []
    try:
        for child in res_root.iterdir():
            if not child.is_dir():
                continue
            if not child.name.startswith(res_type):
                continue
            for ext in _ICON_EXTS:
                cand = child / f"{res_name}{ext}"
                if cand.is_file():
                    variants.append(cand)
    except OSError:
        return ""
    if not variants:
        return ""

    def _density_rank(p: Path) -> int:
        # Higher is better.
        suffix = p.parent.name.split("-", 1)[1] if "-" in p.parent.name else ""
        if not suffix:
            return -1
        for i, density in enumerate(_DENSITY_PREFERENCE):
            if density in suffix:
                return len(_DENSITY_PREFERENCE) - i
        return -2

    variants.sort(key=_density_rank, reverse=True)
    chosen = variants[0]

    dest_dir = job_dir / "meta"
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _LOG.warning("apk_meta: cannot create meta dir: %s", exc)
        return ""

    # Clean up old icon variants so re-extraction never leaves stale files.
    for ext in _ICON_EXTS:
        try:
            (dest_dir / f"icon{ext}").unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    dest = dest_dir / f"icon{chosen.suffix.lower()}"
    try:
        shutil.copy2(chosen, dest)
    except OSError as exc:
        _LOG.warning("apk_meta: cannot copy icon %s -> %s: %s", chosen, dest, exc)
        return ""
    return dest.relative_to(job_dir).as_posix()


# ---------------------------------------------------------------------------
# apktool.yml (best-effort, optional)
# ---------------------------------------------------------------------------

_YML_VALUE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")


def _read_apktool_yml(meta: ApkMeta, yml: Path) -> None:
    """Minimal, regex-based reader so we don't need PyYAML."""
    try:
        text = yml.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    in_sdk = False
    for raw in text.splitlines():
        if raw.startswith("sdkInfo:"):
            in_sdk = True
            continue
        if raw and not raw.startswith((" ", "\t")):
            in_sdk = False

        m = _YML_VALUE_RE.match(raw)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip().strip("'\"")

        if key == "version":
            if not meta.apktool_version:
                meta.apktool_version = value
        elif key == "versionName" and not meta.version_name:
            meta.version_name = value
        elif key == "versionCode" and meta.version_code is None:
            meta.version_code = _to_int(value)
        elif in_sdk and key == "minSdkVersion" and meta.min_sdk is None:
            meta.min_sdk = _to_int(value)
        elif in_sdk and key == "targetSdkVersion" and meta.target_sdk is None:
            meta.target_sdk = _to_int(value)
