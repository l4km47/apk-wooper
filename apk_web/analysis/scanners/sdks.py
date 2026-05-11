from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Pattern, Tuple

from apk_web.analysis.models import Category, Finding, Severity, make_finding
from apk_web.analysis.scanners.base import (
    Scanner,
    line_for_offset,
    snippet_for_offset,
)


@dataclass(frozen=True)
class SdkRule:
    rule_id: str
    title: str
    pattern: Pattern[str]


# Each pattern matches a string that strongly indicates the SDK is bundled
# with the APK. We dedupe on (rule_id, file) so each SDK fires at most
# once per file.
SDK_RULES: Tuple[SdkRule, ...] = (
    SdkRule(
        "sdk.firebase",
        "Firebase SDK present",
        re.compile(r"com/google/firebase/|FirebaseApp\.initializeApp"),
    ),
    SdkRule(
        "sdk.crashlytics",
        "Crashlytics SDK present",
        re.compile(r"com/google/firebase/crashlytics|com/crashlytics/android"),
    ),
    SdkRule(
        "sdk.onesignal",
        "OneSignal SDK present",
        re.compile(r"com/onesignal/|OneSignal\.initWithContext|OneSignal\.setAppId"),
    ),
    SdkRule(
        "sdk.adjust",
        "Adjust SDK present",
        re.compile(r"com/adjust/sdk/"),
    ),
    SdkRule(
        "sdk.appsflyer",
        "AppsFlyer SDK present",
        re.compile(r"com/appsflyer/"),
    ),
    SdkRule(
        "sdk.branch",
        "Branch.io SDK present",
        re.compile(r"io/branch/referral/|Branch\.getAutoInstance"),
    ),
    SdkRule(
        "sdk.mixpanel",
        "Mixpanel SDK present",
        re.compile(r"com/mixpanel/android/"),
    ),
    SdkRule(
        "sdk.amplitude",
        "Amplitude SDK present",
        re.compile(r"com/amplitude/api/|com/amplitude/android/"),
    ),
    SdkRule(
        "sdk.facebook",
        "Facebook SDK present",
        re.compile(r"com/facebook/(?:appevents|login|FacebookSdk)"),
    ),
    SdkRule(
        "sdk.flurry",
        "Flurry Analytics SDK present",
        re.compile(r"com/flurry/(?:android|sdk)/"),
    ),
    SdkRule(
        "sdk.umeng",
        "Umeng SDK present",
        re.compile(r"com/umeng/(?:analytics|commonsdk|message)/"),
    ),
    SdkRule(
        "sdk.applovin",
        "AppLovin SDK present",
        re.compile(r"com/applovin/"),
    ),
    SdkRule(
        "sdk.unity_ads",
        "Unity Ads SDK present",
        re.compile(r"com/unity3d/ads/"),
    ),
    SdkRule(
        "sdk.admob",
        "Google AdMob/Mobile Ads SDK present",
        re.compile(r"com/google/android/gms/ads/"),
    ),
)

_SENTRY_DSN = re.compile(r"\bhttps?://[A-Za-z0-9]{16,}@[A-Za-z0-9._\-]+\.ingest\.sentry\.io/\d+\b")
_SUPABASE_URL = re.compile(r"\bhttps?://[a-z0-9]{16,}\.supabase\.co\b", re.IGNORECASE)
_FACEBOOK_APP_ID = re.compile(r"facebook_app_id[\"'\s>:=]+\s*([0-9]{6,20})", re.IGNORECASE)


class _SdkScanner:
    name = "sdks"
    kind = "text"

    # Track per-job emitted SDKs so we only fire once per SDK (not per file).
    _emitted_keys: set[str] = set()

    def reset(self) -> None:
        self._emitted_keys = set()

    def scan_text(self, *, rel: str, text: str) -> Iterable[Finding]:
        lower = rel.lower()
        # SDK class-path patterns appear in JADX sources / smali / manifest.
        # We allow scanning all text files to also catch references in
        # strings.xml / proguard rules.
        out: List[Finding] = []

        for rule in SDK_RULES:
            if rule.rule_id in self._emitted_keys:
                continue
            m = rule.pattern.search(text)
            if not m:
                continue
            self._emitted_keys.add(rule.rule_id)
            line, col = line_for_offset(text, m.start())
            out.append(
                make_finding(
                    rule_id=rule.rule_id,
                    category=Category.SDK,
                    severity=Severity.INFO,
                    title=rule.title,
                    file=rel,
                    full_match=m.group(0),
                    line=line,
                    column=col,
                    snippet=snippet_for_offset(text, m.start()),
                    tool="signature",
                    confidence=0.85,
                    redact=False,
                )
            )

        # DSN/URL-style SDK fingerprints (these *do* carry an identifier,
        # so we let them fire once per unique match rather than once per
        # rule).
        seen_per_file: set[tuple[str, str]] = set()
        for pat, rule_id, title, severity in (
            (_SENTRY_DSN, "sdk.sentry_dsn", "Sentry DSN", Severity.MEDIUM),
            (_SUPABASE_URL, "sdk.supabase_url", "Supabase project URL", Severity.LOW),
            (_FACEBOOK_APP_ID, "sdk.facebook_app_id", "Facebook App ID", Severity.LOW),
        ):
            for m in pat.finditer(text):
                value = m.group(0)
                key = (rule_id, value)
                if key in seen_per_file:
                    continue
                seen_per_file.add(key)
                line, col = line_for_offset(text, m.start())
                out.append(
                    make_finding(
                        rule_id=rule_id,
                        category=Category.SDK,
                        severity=severity,
                        title=title,
                        file=rel,
                        full_match=value,
                        line=line,
                        column=col,
                        snippet=snippet_for_offset(text, m.start()),
                        tool="regex",
                        confidence=0.95,
                        redact=False,
                    )
                )
        return out

    def scan_native(self, *, rel: str, path: Path) -> Iterable[Finding]:
        return ()

    def scan_global(self, *, job_root: Path) -> Iterable[Finding]:
        return ()


SCANNER: Scanner = _SdkScanner()
