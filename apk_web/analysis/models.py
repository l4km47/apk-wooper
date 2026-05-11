from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def rank(cls, value: "str | Severity") -> int:
        order = {cls.HIGH: 3, cls.MEDIUM: 2, cls.LOW: 1, cls.INFO: 0}
        try:
            return order[cls(value)]
        except (ValueError, KeyError):
            return -1


class Category(str, Enum):
    SECRET = "secret"
    NETWORK = "network"
    MANIFEST = "manifest"
    CRYPTO = "crypto"
    AUTH = "auth"
    SDK = "sdk"
    NATIVE = "native"
    OTHER = "other"


def _redact(value: str, *, keep: int = 4) -> str:
    """Mask the middle of a secret while keeping a recognisable head/tail."""
    if not value:
        return value
    if len(value) <= keep * 2 + 2:
        return value[: max(1, keep)] + "***"
    return f"{value[:keep]}...{value[-keep:]} (len={len(value)})"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: Category
    severity: Severity
    title: str
    file: str
    match: str
    full_match: str = ""
    line: int = 0
    column: int = 0
    snippet: str = ""
    tool: str = "regex"
    confidence: float = 0.7
    extra: Dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        basis = f"{self.rule_id}|{self.file}|{self.line}|{self.full_match or self.match}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        data["id"] = self.fingerprint()
        return data


def make_finding(
    *,
    rule_id: str,
    category: Category,
    severity: Severity,
    title: str,
    file: str,
    full_match: str,
    line: int = 0,
    column: int = 0,
    snippet: str = "",
    tool: str = "regex",
    confidence: float = 0.7,
    extra: Optional[Dict[str, Any]] = None,
    redact: bool = True,
) -> Finding:
    """Constructor helper that auto-redacts the display match for secrets."""
    display = _redact(full_match) if redact and category == Category.SECRET else full_match
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        file=file,
        match=display,
        full_match=full_match,
        line=line,
        column=column,
        snippet=snippet,
        tool=tool,
        confidence=confidence,
        extra=dict(extra or {}),
    )
