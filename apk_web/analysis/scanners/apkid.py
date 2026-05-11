"""APKiD scanner integration.

Wraps `APKiD <https://github.com/rednaga/APKiD>`_ as a ``global`` analysis
scanner. It fingerprints packers, obfuscators, anti-VM/anti-debug
techniques, and the original compiler on the **input APK** rather than
the decompiled tree.

The scanner prefers the in-process Python API to avoid spawning a second
interpreter; if importing the API breaks (e.g. APKiD updates its
internals) it falls back to ``apkid -j <apk>`` via subprocess so we keep
working without code changes.
"""

from __future__ import annotations

import io
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from apk_web.analysis.models import Category, Finding, Severity, make_finding

_LOG = logging.getLogger(__name__)


_SUBPROC_TIMEOUT_SEC = 240
_PY_TIMEOUT_SEC = 240


# Category -> (Severity, Finding-category, human title prefix)
_CATEGORY_MAP: Dict[str, Tuple[Severity, Category, str]] = {
    "packer": (Severity.HIGH, Category.PROTECTION, "Packer detected"),
    "protector": (Severity.HIGH, Category.PROTECTION, "Protector detected"),
    "obfuscator": (Severity.MEDIUM, Category.PROTECTION, "Obfuscator detected"),
    "manipulator": (Severity.MEDIUM, Category.PROTECTION, "Manipulator detected"),
    "anti_vm": (Severity.HIGH, Category.PROTECTION, "Anti-VM technique"),
    "anti_disassembly": (
        Severity.HIGH,
        Category.PROTECTION,
        "Anti-disassembly technique",
    ),
    "anti_debug": (Severity.HIGH, Category.PROTECTION, "Anti-debug technique"),
    "anti_emulator": (Severity.HIGH, Category.PROTECTION, "Anti-emulator technique"),
    "compiler": (Severity.INFO, Category.SDK, "Compiler"),
}


def _slugify(value: str) -> str:
    out = []
    for ch in (value or "").strip().lower():
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "-", "_", "/", "."):
            out.append("_")
    slug = "".join(out).strip("_")
    return slug or "unknown"


class ApkidScanner:
    """Global scanner powered by APKiD's yara rule set."""

    name = "apkid"
    kind = "global"

    def __init__(self) -> None:
        pass

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:  # noqa: D401
        return ()

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:  # noqa: D401
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        apk = job_root / "input.apk"
        if not apk.is_file():
            _LOG.info("apkid: no input.apk under %s; skipping", job_root)
            return ()

        results = _scan_via_python(apk)
        if results is None:
            results = _scan_via_subprocess(apk)
        if results is None:
            return ()

        return list(_findings_from_results(results, file_rel="input.apk"))


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


def _scan_via_python(apk: Path) -> Optional[Dict[str, Any]]:
    """Run APKiD in-process and return its JSON-shaped result dict.

    Returns ``None`` if the Python API is unavailable or fails outright;
    callers should then fall back to the CLI.
    """
    try:
        from apkid.apkid import Options, Scanner  # type: ignore
    except Exception as exc:  # noqa: BLE001
        _LOG.info("apkid: python API unavailable (%s)", exc)
        return None

    try:
        opts = Options(
            timeout=30,
            verbose=False,
            json=True,
            typing="magic",
            entry_max_scan_size=0,
            scan_depth=2,
            recursive=False,
            include_trackers=False,
            include_types=False,
        )
        rules = opts.rules_manager.load()
        scanner = Scanner(rules, opts)
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("apkid: failed to construct scanner (%s)", exc)
        return None

    buf = io.StringIO()
    saved_stdout = sys.stdout
    sys.stdout = buf
    try:
        scanner.scan(str(apk))
    except Exception as exc:  # noqa: BLE001
        _LOG.warning("apkid: in-process scan failed for %s (%s)", apk, exc)
        return None
    finally:
        sys.stdout = saved_stdout

    raw = buf.getvalue().strip()
    if not raw:
        return {"files": []}

    return _coerce_json(raw)


def _scan_via_subprocess(apk: Path) -> Optional[Dict[str, Any]]:
    """Run ``apkid -j`` via subprocess.

    Returns ``None`` if the CLI cannot be located or invocation fails.
    """
    binary = shutil.which("apkid")
    if not binary:
        _LOG.info("apkid: CLI not on PATH; skipping")
        return None

    try:
        proc = subprocess.run(
            [binary, "-j", str(apk)],
            capture_output=True,
            text=True,
            timeout=_SUBPROC_TIMEOUT_SEC,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        _LOG.warning("apkid: subprocess failed for %s (%s)", apk, exc)
        return None

    return _coerce_json(proc.stdout or "")


def _coerce_json(raw: str) -> Optional[Dict[str, Any]]:
    """Parse APKiD JSON output, leniently handling stray prefix lines."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    if start < 0:
        _LOG.warning("apkid: could not locate JSON in output (head=%r)", raw[:80])
        return None
    try:
        return json.loads(raw[start:])
    except json.JSONDecodeError as exc:
        _LOG.warning("apkid: JSON decode failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Result translation
# ---------------------------------------------------------------------------


def _findings_from_results(
    data: Dict[str, Any], *, file_rel: str
) -> Iterable[Finding]:
    """Translate the APKiD JSON report into ``Finding`` objects."""
    if not isinstance(data, dict):
        return
    files = data.get("files")
    if not isinstance(files, list):
        return
    for entry in files:
        if not isinstance(entry, dict):
            continue
        matches = entry.get("matches")
        if not isinstance(matches, dict):
            continue
        sub_filename = str(entry.get("filename") or "")
        # APKiD reports nested entries as "<apk>!classes.dex"; surface that
        # in the snippet so the user knows which inner blob triggered the
        # match, while keeping the displayed file path the on-disk APK.
        inner = sub_filename.split("!", 1)[1] if "!" in sub_filename else None
        for raw_cat, descriptions in matches.items():
            if not isinstance(descriptions, list):
                continue
            cat_key = str(raw_cat).strip().lower()
            severity, category, title_prefix = _CATEGORY_MAP.get(
                cat_key, (Severity.LOW, Category.PROTECTION, "Detection")
            )
            for desc in descriptions:
                if not isinstance(desc, str) or not desc.strip():
                    continue
                slug = _slugify(desc)
                rule_id = f"apkid.{_slugify(cat_key)}.{slug}"
                snippet = f"APKiD: {cat_key} -> {desc}"
                if inner:
                    snippet = f"{snippet} (in {inner})"
                yield make_finding(
                    rule_id=rule_id,
                    category=category,
                    severity=severity,
                    title=f"{title_prefix}: {desc}",
                    file=file_rel,
                    full_match=desc,
                    line=0,
                    column=0,
                    snippet=snippet,
                    tool="apkid",
                    confidence=0.9,
                    extra={
                        "apkid_category": cat_key,
                        "inner_entry": inner,
                    },
                    redact=False,
                )


SCANNER: ApkidScanner = ApkidScanner()
