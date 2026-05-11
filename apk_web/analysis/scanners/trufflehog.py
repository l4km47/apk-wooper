from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Iterable, List

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.scanners.base import Scanner

_LOG = logging.getLogger(__name__)


class TrufflehogScanner:
    """Wraps the ``trufflehog`` CLI in filesystem mode (JSON output)."""

    name = "trufflehog"
    kind = "global"

    def __init__(self, binary: Path, scan_relative: str = "out") -> None:
        self.binary = Path(binary)
        self.scan_relative = scan_relative

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        return ()

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        scan_dir = job_root / self.scan_relative
        if not scan_dir.is_dir():
            scan_dir = job_root
        if not self.binary.is_file():
            return ()

        argv = [
            str(self.binary),
            "filesystem",
            str(scan_dir),
            "--json",
            "--no-update",
            "--no-verification",
        ]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _LOG.warning("trufflehog execution failed: %s", exc)
            return ()

        out: List[Finding] = []
        for raw in (proc.stdout or "").splitlines():
            raw = raw.strip()
            if not raw or not raw.startswith("{"):
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            src = item.get("SourceMetadata") or {}
            file_field = (
                src.get("Data", {})
                .get("Filesystem", {})
                .get("file")
                or ""
            )
            file_path = file_field.replace("\\", "/")
            if file_path.startswith(str(job_root).replace("\\", "/")):
                try:
                    file_path = (
                        Path(file_path).resolve().relative_to(job_root.resolve()).as_posix()
                    )
                except ValueError:
                    pass
            detector = (item.get("DetectorName") or "unknown").lower()
            raw_secret = item.get("Raw") or ""
            line = (
                src.get("Data", {})
                .get("Filesystem", {})
                .get("line")
                or 0
            )
            verified = bool(item.get("Verified"))
            severity = Severity.HIGH if verified else Severity.MEDIUM
            out.append(
                make_finding(
                    rule_id=f"trufflehog.{detector}",
                    category=Category.SECRET,
                    severity=severity,
                    title=f"trufflehog detector: {detector}"
                    + (" (verified)" if verified else ""),
                    file=file_path,
                    full_match=raw_secret,
                    line=int(line) if isinstance(line, (int, float)) else 0,
                    snippet="",
                    tool="trufflehog",
                    confidence=0.97 if verified else 0.7,
                    redact=True,
                    extra={"verified": verified},
                )
            )
        return out
