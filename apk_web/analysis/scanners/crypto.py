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


_CIPHER_AES_ECB = re.compile(
    r"""Cipher\.getInstance\(\s*['"]\s*AES/ECB/[^'"]+['"]""",
    re.IGNORECASE,
)
_CIPHER_WEAK = re.compile(
    r"""Cipher\.getInstance\(\s*['"]\s*(DES|DESede|RC2|RC4|Blowfish)\b[^'"]*['"]""",
    re.IGNORECASE,
)
_MESSAGE_DIGEST_WEAK = re.compile(
    r"""MessageDigest\.getInstance\(\s*['"]\s*(MD5|MD4|MD2|SHA-?1)\s*['"]""",
    re.IGNORECASE,
)
# Hardcoded byte arrays of crypto-key length fed into a SecretKeySpec
# constructor — matches both decompiled Java and the smali equivalents.
_SECRET_KEY_SPEC = re.compile(
    r"new\s+SecretKeySpec\s*\(\s*(?:new\s+byte\[\]\s*\{[^}]{30,}\}|\"[^\"]{16,}\"\.getBytes\(\))",
)
_SMALI_SECRET_KEY_SPEC = re.compile(
    r"Ljavax/crypto/spec/SecretKeySpec;-><init>\([^)]*\)V",
)
# OkHttp/Conscrypt trust-all bypass markers.
_TRUST_ALL = re.compile(
    r"(?:checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|"
    r"X509TrustManager\s*\{\s*[^}]*?return\s*null|"
    r"setHostnameVerifier\s*\(\s*new\s+HostnameVerifier[^)]*\)\s*\{\s*[^}]*?return\s+true)",
    re.DOTALL,
)


class _CryptoScanner:
    name = "crypto"
    kind = "text"

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        # Limit to relevant decompiled output to keep noise low.
        lower = rel.lower()
        if not (
            lower.endswith(".java")
            or lower.endswith(".kt")
            or lower.endswith(".smali")
        ):
            return ()
        out: List[Finding] = []
        seen: set[tuple[str, int]] = set()

        def _emit(rule_id: str, severity: Severity, title: str, m: "re.Match[str]") -> None:
            line, col = line_for_offset(text, m.start())
            key = (rule_id, line)
            if key in seen:
                return
            seen.add(key)
            out.append(
                make_finding(
                    rule_id=rule_id,
                    category=Category.CRYPTO,
                    severity=severity,
                    title=title,
                    file=rel,
                    full_match=m.group(0),
                    line=line,
                    column=col,
                    snippet=snippet_for_offset(text, m.start()),
                    tool="regex",
                    confidence=0.8,
                    redact=False,
                )
            )

        for m in _CIPHER_AES_ECB.finditer(text):
            _emit("crypto.aes_ecb", Severity.HIGH, "AES/ECB mode in Cipher.getInstance", m)
        for m in _CIPHER_WEAK.finditer(text):
            algo = m.group(1)
            _emit(
                "crypto.weak_cipher",
                Severity.MEDIUM,
                f"Weak cipher algorithm: {algo}",
                m,
            )
        for m in _MESSAGE_DIGEST_WEAK.finditer(text):
            algo = m.group(1)
            _emit(
                "crypto.weak_hash",
                Severity.LOW,
                f"Weak hash algorithm: {algo}",
                m,
            )
        for m in _SECRET_KEY_SPEC.finditer(text):
            _emit(
                "crypto.hardcoded_key",
                Severity.MEDIUM,
                "Hardcoded key passed to SecretKeySpec",
                m,
            )
        if lower.endswith(".smali"):
            for m in _SMALI_SECRET_KEY_SPEC.finditer(text):
                _emit(
                    "crypto.smali_secret_key_spec",
                    Severity.LOW,
                    "SecretKeySpec constructor invoked (review for hardcoded key)",
                    m,
                )
        for m in _TRUST_ALL.finditer(text):
            _emit(
                "crypto.trust_all",
                Severity.HIGH,
                "Possible TLS verification bypass (trust-all)",
                m,
            )

        return out

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        return ()


SCANNER: Scanner = _CryptoScanner()
