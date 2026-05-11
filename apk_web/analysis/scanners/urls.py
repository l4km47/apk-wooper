from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List
from urllib.parse import urlparse

from apk_web.analysis.models import Finding, make_finding
from apk_web.analysis.patterns import IPV4_NOISE_PREFIXES, URL_NOISE_HOSTS, URL_RULES
from apk_web.analysis.scanners.base import (
    Scanner,
    iter_pattern_hits,
    line_for_offset,
    snippet_for_offset,
)


_RETROFIT_BASEURL = re.compile(
    r"\.baseUrl\s*\(\s*[\"']([^\"']{6,200})[\"']\s*\)",
)


def _host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def _is_noise_ip(value: str) -> bool:
    return any(value.startswith(prefix) for prefix in IPV4_NOISE_PREFIXES)


class _UrlsScanner:
    name = "urls"
    kind = "text"

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        out: List[Finding] = []
        seen: set[tuple[str, str]] = set()

        for rule, m in iter_pattern_hits(text, URL_RULES):
            value = m.group(0).rstrip(".,;:)\"'>")
            if not value:
                continue
            if rule.rule_id in ("net.http_url", "net.ws_url"):
                host = _host_of(value)
                if host in URL_NOISE_HOSTS:
                    continue
            elif rule.rule_id == "net.ipv4":
                if _is_noise_ip(value):
                    continue
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

        if rel.endswith(".java") or rel.endswith(".kt"):
            for m in _RETROFIT_BASEURL.finditer(text):
                value = m.group(1)
                key = ("net.retrofit_baseurl", value)
                if key in seen:
                    continue
                seen.add(key)
                line, col = line_for_offset(text, m.start(1))
                snippet = snippet_for_offset(text, m.start(1))
                out.append(
                    make_finding(
                        rule_id="net.retrofit_baseurl",
                        category=URL_RULES[0].category,
                        severity=URL_RULES[0].severity,
                        title="Retrofit/OkHttp base URL",
                        file=rel,
                        full_match=value,
                        line=line,
                        column=col,
                        snippet=snippet,
                        tool="regex",
                        confidence=0.85,
                        redact=False,
                    )
                )
        return out

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        return ()


SCANNER: Scanner = _UrlsScanner()
