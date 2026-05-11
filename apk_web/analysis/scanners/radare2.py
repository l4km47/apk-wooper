from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Iterable, List

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.scanners.base import Scanner

_LOG = logging.getLogger(__name__)


class Radare2Scanner:
    """Uses ``r2`` to enrich .so analysis with imports/exports/entries.

    Runs in addition to the built-in native scanner; results are tagged
    ``tool="radare2"`` so the UI can distinguish them.
    """

    name = "radare2"
    kind = "native"

    def __init__(self, binary: Path) -> None:
        self.binary = Path(binary)

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        return ()

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        if not self.binary.is_file():
            return ()
        argv = [str(self.binary), "-qc", "iEj; iij; iej", str(path)]
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _LOG.warning("radare2 failed on %s: %s", path, exc)
            return ()
        out: List[Finding] = []
        # r2 emits each command's output on its own line as JSON.
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line or not line.startswith(("[", "{")):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list):
                for item in data[:80]:
                    name = item.get("name") if isinstance(item, dict) else None
                    if not name:
                        continue
                    sym_type = item.get("type") or "symbol"
                    out.append(
                        make_finding(
                            rule_id=f"native.r2_{sym_type}",
                            category=Category.NATIVE,
                            severity=Severity.INFO,
                            title=f"{sym_type}: {name}",
                            file=rel,
                            full_match=name,
                            tool="radare2",
                            confidence=0.95,
                            redact=False,
                        )
                    )
        return out
