from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.scanners.base import (
    Scanner,
    line_for_offset,
    snippet_for_offset,
)


_BASIC_AUTH = re.compile(
    r"""Authorization\s*[:=]\s*["']?\s*Basic\s+([A-Za-z0-9+/=]{8,})""",
    re.IGNORECASE,
)
_BEARER = re.compile(
    r"""Authorization\s*[:=]\s*["']?\s*Bearer\s+([A-Za-z0-9._\-]{16,})""",
    re.IGNORECASE,
)
_OAUTH_REDIRECT = re.compile(
    r"""redirect_uri\s*[:=]\s*["']([^"']{8,200})["']""",
    re.IGNORECASE,
)


class _AuthScanner:
    name = "auth"
    kind = "text"

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        out: List[Finding] = []
        seen: set[tuple[str, str]] = set()

        def _emit(rule_id: str, severity: Severity, title: str, m: "re.Match[str]", *, redact: bool) -> None:
            value = m.group(0)
            key = (rule_id, value)
            if key in seen:
                return
            seen.add(key)
            line, col = line_for_offset(text, m.start())
            out.append(
                make_finding(
                    rule_id=rule_id,
                    category=Category.AUTH,
                    severity=severity,
                    title=title,
                    file=rel,
                    full_match=value,
                    line=line,
                    column=col,
                    snippet=snippet_for_offset(text, m.start()),
                    tool="regex",
                    confidence=0.9,
                    redact=redact,
                )
            )

        for m in _BASIC_AUTH.finditer(text):
            _emit("auth.basic_header", Severity.HIGH, "Hardcoded Basic auth header", m, redact=True)
        for m in _BEARER.finditer(text):
            _emit("auth.bearer_literal", Severity.HIGH, "Hardcoded Bearer token", m, redact=True)
        for m in _OAUTH_REDIRECT.finditer(text):
            _emit("auth.oauth_redirect", Severity.LOW, "OAuth redirect_uri", m, redact=False)

        return out

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        return ()


SCANNER: Scanner = _AuthScanner()
