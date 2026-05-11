from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.scanners.base import Scanner

_LOG = logging.getLogger(__name__)


class GitleaksScanner:
    """Wraps the ``gitleaks`` CLI in directory scan mode."""

    name = "gitleaks"
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

        with _tempjson() as report_path:
            argv = [
                str(self.binary),
                "dir",
                str(scan_dir),
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
                "--exit-code",
                "0",
            ]
            try:
                proc = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                _LOG.warning("gitleaks execution failed: %s", exc)
                return ()
            if proc.returncode not in (0, 1):  # gitleaks returns 1 when findings exist
                _LOG.warning("gitleaks exited %s: %s", proc.returncode, proc.stderr[:500])
            try:
                data = json.loads(report_path.read_text(encoding="utf-8") or "[]")
            except (OSError, json.JSONDecodeError):
                return ()

        out: List[Finding] = []
        for item in data or []:
            file_path = (item.get("File") or "").replace("\\", "/")
            if file_path.startswith(str(job_root).replace("\\", "/")):
                file_path = Path(file_path).resolve().relative_to(job_root.resolve()).as_posix()
            rule_id = (item.get("RuleID") or "gitleaks.unknown").lower()
            secret = item.get("Secret") or ""
            description = item.get("Description") or rule_id
            line = item.get("StartLine") or 0
            column = item.get("StartColumn") or 0
            snippet = item.get("Match") or ""
            out.append(
                make_finding(
                    rule_id=f"gitleaks.{rule_id}",
                    category=Category.SECRET,
                    severity=Severity.HIGH,
                    title=description,
                    file=file_path,
                    full_match=secret,
                    line=int(line) if isinstance(line, (int, float)) else 0,
                    column=int(column) if isinstance(column, (int, float)) else 0,
                    snippet=snippet[:200],
                    tool="gitleaks",
                    confidence=0.95,
                    redact=True,
                )
            )
        return out


import tempfile


class _tempjson:
    def __init__(self) -> None:
        self._path: Optional[Path] = None

    def __enter__(self) -> Path:
        fd, name = tempfile.mkstemp(prefix="gitleaks-report-", suffix=".json")
        import os

        os.close(fd)
        self._path = Path(name)
        return self._path

    def __exit__(self, *exc) -> None:
        try:
            if self._path and self._path.is_file():
                self._path.unlink()
        except OSError:
            pass
