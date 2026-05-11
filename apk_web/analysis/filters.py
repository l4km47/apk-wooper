"""File-system filters for the analysis engine.

Decides which files the text scanners should read, which should be left
to binary scanners (.so), and which to skip entirely (images, fonts,
media). Conservative include lists keep the worker pool focused on the
files where decompiled Java/smali secrets actually live.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Tuple


TEXT_EXTENSIONS = frozenset(
    {
        "java",
        "kt",
        "kts",
        "groovy",
        "smali",
        "xml",
        "json",
        "properties",
        "cfg",
        "ini",
        "toml",
        "yml",
        "yaml",
        "txt",
        "md",
        "gradle",
        "pro",
        "html",
        "js",
        "ts",
        "css",
        "csv",
        "tsv",
        "env",
        "conf",
        "sf",
        "mf",
        "rsa",
        "pem",
        "crt",
        "cer",
    }
)

NATIVE_EXTENSIONS = frozenset({"so"})

# Files we deliberately leave to dedicated scanners or skip entirely.
SKIP_EXTENSIONS = frozenset(
    {
        "png",
        "jpg",
        "jpeg",
        "webp",
        "gif",
        "bmp",
        "ico",
        "svg",
        "ttf",
        "otf",
        "woff",
        "woff2",
        "mp3",
        "mp4",
        "webm",
        "mov",
        "wav",
        "ogg",
        "flac",
        "dex",
        "arsc",
        "zip",
        "jar",
        "apk",
        "aar",
        "pdf",
        "psd",
        "bin",
        "dat",
        "db",
        "sqlite",
    }
)

# Directories that contain nothing scanners should ever read.
SKIP_DIRECTORY_NAMES = frozenset({"__MACOSX"})


def _ext(path: Path) -> str:
    suf = path.suffix
    return suf[1:].lower() if suf else ""


def classify_file(path: Path) -> str:
    """Return one of 'text', 'native', 'skip'.

    Unknown extensions are treated as text only if the file is small
    enough; the caller can re-classify based on size or content sniffing.
    """
    ext = _ext(path)
    if ext in NATIVE_EXTENSIONS:
        return "native"
    if ext in SKIP_EXTENSIONS:
        return "skip"
    if ext in TEXT_EXTENSIONS or ext == "":
        return "text"
    return "text"


def iter_scan_candidates(root: Path) -> Iterator[Tuple[Path, str]]:
    """Walk *root* yielding (absolute_path, classification) pairs."""
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRECTORY_NAMES for part in path.parts):
            continue
        kind = classify_file(path)
        if kind == "skip":
            continue
        yield path, kind


def looks_binary(sample: bytes, *, threshold: float = 0.30) -> bool:
    """Heuristic: treat a file as binary if too many bytes are not printable.

    Bytes are 'printable' here if they fall in the ASCII 9..13/32..126
    range, plus high-bit UTF-8 continuation bytes. Tuned to keep XML/JSON
    classified as text while skipping arbitrary binary blobs.
    """
    if not sample:
        return False
    bad = 0
    for b in sample:
        if b in (9, 10, 13):
            continue
        if 32 <= b <= 126:
            continue
        if b >= 0x80:
            # UTF-8 continuation / multi-byte start; do not count
            continue
        bad += 1
    return (bad / len(sample)) > threshold


def filter_paths(paths: Iterable[Tuple[Path, str]], *, text_max_bytes: int, native_max_bytes: int):
    """Drop files that exceed the per-class size cap; preserve order."""
    for path, kind in paths:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if kind == "text" and size > text_max_bytes:
            continue
        if kind == "native" and size > native_max_bytes:
            continue
        yield path, kind, size
