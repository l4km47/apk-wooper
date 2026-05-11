from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Protocol, runtime_checkable

from apk_web.analysis.models import Finding


@runtime_checkable
class Scanner(Protocol):
    """A static-analysis scanner.

    Scanners declare a ``kind`` (``"text"``, ``"native"``, or ``"global"``)
    and implement the matching ``scan_*`` method. The engine picks the
    right method based on file classification.
    """

    name: str
    kind: str

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:  # pragma: no cover - protocol
        ...

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:  # pragma: no cover
        ...

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:  # pragma: no cover
        ...


def line_for_offset(text: str, offset: int) -> tuple[int, int]:
    """Return 1-indexed (line, column) for a given byte offset in *text*."""
    if offset <= 0:
        return (1, 1)
    head = text[:offset]
    line = head.count("\n") + 1
    nl = head.rfind("\n")
    column = offset - nl if nl >= 0 else offset + 1
    return (line, column)


def snippet_for_offset(text: str, offset: int, *, before: int = 40, after: int = 80) -> str:
    """Return a single-line snippet centred on *offset*."""
    start = max(0, offset - before)
    end = min(len(text), offset + after)
    raw = text[start:end].replace("\r", " ").replace("\n", " ")
    return raw.strip()


def iter_pattern_hits(
    text: str,
    rules: Iterable,
) -> Iterator[tuple]:
    """Yield ``(rule, match)`` tuples for every pattern hit in *text*."""
    for rule in rules:
        for m in rule.pattern.finditer(text):
            yield rule, m
