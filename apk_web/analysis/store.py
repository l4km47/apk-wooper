from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List

from apk_web.analysis.models import Finding


class AnalysisStore:
    """Filesystem-backed store for per-job analysis output.

    Layout under ``<job_dir>/analysis/``:
        - ``findings.json``  -> list of finding dicts
        - ``summary.json``   -> aggregate counts + meta
        - ``progress.json``  -> live progress while running
        - ``ignores.json``   -> ignore rules (optional, written by UI)
    """

    def __init__(self, job_dir: Path) -> None:
        self.job_dir = Path(job_dir)
        self.dir = self.job_dir / "analysis"

    def ensure_dir(self) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        return self.dir

    @property
    def findings_path(self) -> Path:
        return self.dir / "findings.json"

    @property
    def summary_path(self) -> Path:
        return self.dir / "summary.json"

    @property
    def progress_path(self) -> Path:
        return self.dir / "progress.json"

    @property
    def ignores_path(self) -> Path:
        return self.dir / "ignores.json"

    @property
    def log_path(self) -> Path:
        return self.dir / "analysis.log"

    def append_log(self, text: str) -> None:
        try:
            self.ensure_dir()
            with self.log_path.open("a", encoding="utf-8", errors="replace") as fp:
                fp.write(text if text.endswith("\n") else text + "\n")
        except OSError:
            pass

    def reset_log(self) -> None:
        try:
            self.ensure_dir()
            self.log_path.write_text("", encoding="utf-8")
        except OSError:
            pass

    def read_log(self, *, tail_bytes: int = 64 * 1024) -> str:
        if not self.log_path.is_file():
            return ""
        try:
            data = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        if tail_bytes and len(data) > tail_bytes:
            return data[-tail_bytes:]
        return data

    def has_results(self) -> bool:
        return self.findings_path.is_file() and self.summary_path.is_file()

    def _atomic_write_json(self, path: Path, payload: Any) -> None:
        self.ensure_dir()
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".",
            suffix=".tmp",
            dir=str(self.dir),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, indent=2, ensure_ascii=False)
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def write_findings(self, findings: Iterable[Finding]) -> int:
        payload = [f.to_dict() for f in findings]
        self._atomic_write_json(self.findings_path, payload)
        return len(payload)

    def write_summary(self, payload: Dict[str, Any]) -> None:
        self._atomic_write_json(self.summary_path, payload)

    def write_progress(self, payload: Dict[str, Any]) -> None:
        try:
            self._atomic_write_json(self.progress_path, payload)
        except OSError:
            # Progress writes are best-effort.
            pass

    def clear_progress(self) -> None:
        try:
            if self.progress_path.is_file():
                self.progress_path.unlink()
        except OSError:
            pass

    def read_findings(self) -> List[Dict[str, Any]]:
        if not self.findings_path.is_file():
            return []
        try:
            return json.loads(self.findings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

    def read_summary(self) -> Dict[str, Any]:
        if not self.summary_path.is_file():
            return {}
        try:
            return json.loads(self.summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def read_progress(self) -> Dict[str, Any]:
        if not self.progress_path.is_file():
            return {}
        try:
            return json.loads(self.progress_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def read_ignores(self) -> Dict[str, Any]:
        if not self.ignores_path.is_file():
            return {"rules": [], "fingerprints": []}
        try:
            data = json.loads(self.ignores_path.read_text(encoding="utf-8"))
            return {
                "rules": list(data.get("rules") or []),
                "fingerprints": list(data.get("fingerprints") or []),
            }
        except (OSError, json.JSONDecodeError):
            return {"rules": [], "fingerprints": []}

    def write_ignores(self, payload: Dict[str, Any]) -> None:
        self._atomic_write_json(
            self.ignores_path,
            {
                "rules": list(payload.get("rules") or []),
                "fingerprints": list(payload.get("fingerprints") or []),
            },
        )
