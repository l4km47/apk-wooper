from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from apk_web.analysis.models import Finding, make_finding
from apk_web.analysis.patterns import SECRET_RULES
from apk_web.analysis.scanners.base import (
    Scanner,
    iter_pattern_hits,
    line_for_offset,
    snippet_for_offset,
)


class _SecretsScanner:
    name = "secrets"
    kind = "text"

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        out: List[Finding] = []
        seen: set[tuple[str, str]] = set()
        for rule, m in iter_pattern_hits(text, SECRET_RULES):
            value = m.group(0)
            key = (rule.rule_id, value)
            if key in seen:
                continue
            seen.add(key)
            line, col = line_for_offset(text, m.start())
            snippet = snippet_for_offset(text, m.start())
            out.append(
                make_finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    title=rule.title,
                    file=rel,
                    full_match=value,
                    line=line,
                    column=col,
                    snippet=snippet,
                    tool="regex",
                    confidence=rule.confidence,
                    redact=rule.redact,
                )
            )
        return out

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        return ()


SCANNER: Scanner = _SecretsScanner()
