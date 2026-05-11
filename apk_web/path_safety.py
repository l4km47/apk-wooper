from __future__ import annotations

from pathlib import Path


def safe_relative_path(root: Path, rel: str) -> Path:
    """
    Return a resolved path under root, or raise if rel escapes root.
    rel uses forward slashes; backslashes normalized.
    """
    if rel is None:
        raise ValueError("path required")
    s = rel.replace("\\", "/").strip()
    if not s or s == ".":
        return root.resolve()
    p = Path(s)
    if p.is_absolute():
        raise ValueError("absolute paths are not allowed")
    for part in p.parts:
        if part in ("", ".", "/"):
            continue
        if part == "..":
            raise ValueError("path traversal")
    candidate = (root / p).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as e:
        raise ValueError("path outside workspace") from e
    return candidate
