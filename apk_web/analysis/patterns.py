"""Centralized regex catalog for secret + URL detectors.

Each entry is compiled once at import time so scanners can iterate it
without paying re-compilation cost per file. Patterns intentionally err
on the side of recall; the engine de-duplicates and scanners attach
confidence/severity metadata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from apk_web.analysis.models import Category, Severity


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    title: str
    category: Category
    severity: Severity
    pattern: Pattern[str]
    confidence: float = 0.7
    redact: bool = True


def _c(p: str, flags: int = 0) -> Pattern[str]:
    return re.compile(p, flags)


SECRET_RULES: List[PatternRule] = [
    PatternRule(
        rule_id="secret.firebase_api_key",
        title="Google / Firebase API key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.firebase_url",
        title="Firebase Realtime Database URL",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        pattern=_c(r"\bhttps?://[a-z0-9][a-z0-9\-]{2,62}\.firebaseio\.com\b", re.IGNORECASE),
        confidence=0.9,
        redact=False,
    ),
    PatternRule(
        rule_id="secret.fcm_server_key",
        title="Firebase Cloud Messaging legacy server key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b"),
        confidence=0.97,
    ),
    PatternRule(
        rule_id="secret.google_oauth_client_id",
        title="Google OAuth client ID",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        pattern=_c(r"\b\d{8,}-[a-z0-9]{16,40}\.apps\.googleusercontent\.com\b"),
        confidence=0.95,
        redact=False,
    ),
    PatternRule(
        rule_id="secret.openai",
        title="OpenAI API key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
        confidence=0.85,
    ),
    PatternRule(
        rule_id="secret.anthropic",
        title="Anthropic API key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.stripe_live",
        title="Stripe live secret key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
        confidence=0.98,
    ),
    PatternRule(
        rule_id="secret.stripe_publishable_live",
        title="Stripe live publishable key",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        pattern=_c(r"\bpk_live_[A-Za-z0-9]{20,}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.stripe_test",
        title="Stripe test secret key",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        pattern=_c(r"\b(?:sk|rk|pk)_test_[A-Za-z0-9]{20,}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.aws_access_key",
        title="AWS access key ID",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bAKIA[0-9A-Z]{16}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.aws_temp_access_key",
        title="AWS temporary access key ID",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bASIA[0-9A-Z]{16}\b"),
        confidence=0.9,
    ),
    PatternRule(
        rule_id="secret.slack_token",
        title="Slack token",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.github_token",
        title="GitHub token",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bgh[oprsu]_[A-Za-z0-9]{30,}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.twilio_sid",
        title="Twilio account SID",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        pattern=_c(r"\bAC[a-f0-9]{32}\b"),
        confidence=0.85,
    ),
    PatternRule(
        rule_id="secret.sendgrid_key",
        title="SendGrid API key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{32,64}\b"),
        confidence=0.95,
    ),
    PatternRule(
        rule_id="secret.mapbox_token",
        title="Mapbox access token",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        pattern=_c(r"\bpk\.eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{20,}\b"),
        confidence=0.9,
    ),
    PatternRule(
        rule_id="secret.jwt",
        title="JSON Web Token",
        category=Category.SECRET,
        severity=Severity.MEDIUM,
        pattern=_c(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,}\b"),
        confidence=0.85,
    ),
    PatternRule(
        rule_id="secret.pem_private_key",
        title="PEM-encoded private key",
        category=Category.SECRET,
        severity=Severity.HIGH,
        pattern=_c(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        confidence=0.99,
    ),
]


URL_RULES: List[PatternRule] = [
    PatternRule(
        rule_id="net.http_url",
        title="HTTP/HTTPS URL",
        category=Category.NETWORK,
        severity=Severity.LOW,
        pattern=_c(r"\bhttps?://[A-Za-z0-9._~%\-]+(?::\d{1,5})?(?:/[^\s\"'<>`]*)?"),
        confidence=0.6,
        redact=False,
    ),
    PatternRule(
        rule_id="net.ws_url",
        title="WebSocket URL",
        category=Category.NETWORK,
        severity=Severity.LOW,
        pattern=_c(r"\bwss?://[A-Za-z0-9._~%\-]+(?::\d{1,5})?(?:/[^\s\"'<>`]*)?"),
        confidence=0.7,
        redact=False,
    ),
    PatternRule(
        rule_id="net.ipv4",
        title="Hardcoded IPv4 address",
        category=Category.NETWORK,
        severity=Severity.LOW,
        pattern=_c(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
        confidence=0.4,
        redact=False,
    ),
]


ALL_PATTERN_RULES: List[PatternRule] = SECRET_RULES + URL_RULES


# Hosts that produce constant high-volume false positives. The URL scanner
# filters these out before emitting a finding.
URL_NOISE_HOSTS = frozenset(
    {
        "schemas.android.com",
        "www.w3.org",
        "xmlns.android.com",
        "ns.adobe.com",
        "www.apache.org",
        "java.sun.com",
        "xml.apache.org",
        "openjdk.org",
        "www.unicode.org",
        "www.iana.org",
        "www.opengis.net",
        "schemas.xmlsoap.org",
        "purl.org",
    }
)


# IPv4 noise: documentation/private/loopback. We still scan them but tag
# them as low-confidence so the UI can hide by default.
IPV4_NOISE_PREFIXES = ("0.", "127.", "10.", "192.168.", "169.254.", "224.", "239.")
