"""Each rule must match a known-good fixture and reject a near-miss."""

from __future__ import annotations

import pytest

from apk_web.analysis.patterns import ALL_PATTERN_RULES


POSITIVE_CASES = {
    "secret.firebase_api_key": [
        'String k = "AIzaSyA1234567890abcdefghijklmnopqrstuv";',
    ],
    "secret.firebase_url": [
        '"https://my-app-12345.firebaseio.com"',
    ],
    "secret.fcm_server_key": [
        '"AAAAabc1234:' + ("abcdefghij" * 14) + '"',
    ],
    "secret.google_oauth_client_id": [
        '"12345678-abcdefghijklmnop1234567890123abc.apps.googleusercontent.com"',
    ],
    "secret.openai": [
        '"sk-abcdefghijklmnopqrstuvwxyz1234567890"',
        '"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"',
    ],
    "secret.anthropic": [
        '"sk-ant-abcdefghijklmnopqrstuv0123-_"',
    ],
    "secret.stripe_live": [
        '"sk_live_abcdefghijklmnopqrstuvwx"',
        '"rk_live_abcdefghijklmnopqrstuvwx"',
    ],
    "secret.stripe_publishable_live": [
        '"pk_live_abcdefghijklmnopqrstuvwx"',
    ],
    "secret.stripe_test": [
        '"sk_test_abcdefghijklmnopqrstuvwx"',
    ],
    "secret.aws_access_key": [
        '"AKIAIOSFODNN7EXAMPLE"',
    ],
    "secret.aws_temp_access_key": [
        '"ASIAIOSFODNN7TEMPABC"',
    ],
    "secret.slack_token": [
        '"xoxb-1234567890-abcdef"',
        '"xoxp-1234567890-abcdef"',
    ],
    "secret.github_token": [
        '"ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
        '"gho_abcdefghijklmnopqrstuvwxyz0123456789"',
    ],
    "secret.twilio_sid": [
        '"AC0123456789abcdef0123456789abcdef"',
    ],
    "secret.sendgrid_key": [
        '"SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789abcdef"',
    ],
    "secret.mapbox_token": [
        '"pk.eyJ' + "a" * 70 + ".abcdefghijklmnopqrstuv0123-_\"",
    ],
    "secret.jwt": [
        '"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghij"',
    ],
    "secret.pem_private_key": [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
    "net.http_url": [
        "https://api.example.com/v1/users",
    ],
    "net.ws_url": [
        "wss://chat.example.com/socket",
    ],
    "net.ipv4": [
        "8.8.8.8",
    ],
}


NEGATIVE_CASES = {
    "secret.aws_access_key": "AKIA123",  # too short
    "secret.openai": "sk-tiny",  # too short
    "secret.stripe_live": "sk_live_short",  # too short
    "secret.firebase_api_key": "AIzaSyTOOSHORT",  # too short
    "net.http_url": "ftp://nope.example.com",  # wrong scheme
}


@pytest.mark.parametrize("rule_id,examples", POSITIVE_CASES.items())
def test_rule_matches_known_good(rule_id: str, examples: list[str]) -> None:
    rule = next(r for r in ALL_PATTERN_RULES if r.rule_id == rule_id)
    for ex in examples:
        assert rule.pattern.search(ex), f"{rule_id} did not match {ex!r}"


@pytest.mark.parametrize("rule_id,sample", NEGATIVE_CASES.items())
def test_rule_rejects_near_miss(rule_id: str, sample: str) -> None:
    rule = next(r for r in ALL_PATTERN_RULES if r.rule_id == rule_id)
    assert not rule.pattern.search(sample), f"{rule_id} unexpectedly matched {sample!r}"
