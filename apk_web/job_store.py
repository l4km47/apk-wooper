from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobStore:
    def __init__(self, workspaces_root: Path) -> None:
        self.root = workspaces_root
        self.root.mkdir(parents=True, exist_ok=True)

    def job_dir(self, job_id: str) -> Path:
        return self.root / job_id

    def meta_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "meta.json"

    def log_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "job.log"

    def create_job(self, original_filename: str) -> str:
        job_id = str(uuid.uuid4())
        d = self.job_dir(job_id)
        d.mkdir(parents=True)
        meta = {
            "id": job_id,
            "status": "queued",
            "created_at": _utc_now_iso(),
            "updated_at": _utc_now_iso(),
            "original_filename": original_filename,
            "error_message": None,
            "log_excerpt": "",
        }
        self._write_meta(job_id, meta)
        self.log_path(job_id).write_text("", encoding="utf-8")
        return job_id

    def _read_meta(self, job_id: str) -> Dict[str, Any]:
        p = self.meta_path(job_id)
        return json.loads(p.read_text(encoding="utf-8"))

    def _write_meta(self, job_id: str, data: Dict[str, Any]) -> None:
        data["updated_at"] = _utc_now_iso()
        p = self.meta_path(job_id)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def update_meta(self, job_id: str, **kwargs: Any) -> None:
        m = self._read_meta(job_id)
        for k, v in kwargs.items():
            m[k] = v
        self._write_meta(job_id, m)

    def get_meta(self, job_id: str) -> Dict[str, Any]:
        p = self.meta_path(job_id)
        if not p.is_file():
            raise FileNotFoundError(job_id)
        return self._read_meta(job_id)

    def append_log(self, job_id: str, text: str, *, max_excerpt: int = 12000) -> None:
        lp = self.log_path(job_id)
        with lp.open("a", encoding="utf-8", errors="replace") as f:
            f.write(text)
        excerpt = lp.read_text(encoding="utf-8", errors="replace")[-max_excerpt:]
        self.update_meta(job_id, log_excerpt=excerpt)

    def list_jobs(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows: List[tuple[float, Dict[str, Any]]] = []
        if not self.root.is_dir():
            return []
        for child in self.root.iterdir():
            if not child.is_dir():
                continue
            mp = child / "meta.json"
            if not mp.is_file():
                continue
            try:
                mtime = mp.stat().st_mtime
                meta = json.loads(mp.read_text(encoding="utf-8"))
                rows.append((mtime, meta))
            except (OSError, json.JSONDecodeError, ValueError):
                continue
        rows.sort(key=lambda x: x[0], reverse=True)
        return [m for _, m in rows[:limit]]

    def delete_job(self, job_id: str) -> None:
        import shutil

        d = self.job_dir(job_id)
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)
