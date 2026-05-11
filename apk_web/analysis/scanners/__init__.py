"""Scanner registry.

Each module exports a top-level ``SCANNER`` instance implementing the
:class:`apk_web.analysis.scanners.base.Scanner` protocol. The engine
imports the list below and dispatches per-file according to scanner
kind.
"""

from apk_web.analysis.scanners.auth import SCANNER as AUTH_SCANNER
from apk_web.analysis.scanners.base import Scanner
from apk_web.analysis.scanners.crypto import SCANNER as CRYPTO_SCANNER
from apk_web.analysis.scanners.google_services import SCANNER as GOOGLE_SERVICES_SCANNER
from apk_web.analysis.scanners.manifest import SCANNER as MANIFEST_SCANNER
from apk_web.analysis.scanners.native import SCANNER as NATIVE_SCANNER
from apk_web.analysis.scanners.sdks import SCANNER as SDK_SCANNER
from apk_web.analysis.scanners.secrets import SCANNER as SECRETS_SCANNER
from apk_web.analysis.scanners.urls import SCANNER as URLS_SCANNER

DEFAULT_SCANNERS: list[Scanner] = [
    SECRETS_SCANNER,
    URLS_SCANNER,
    AUTH_SCANNER,
    CRYPTO_SCANNER,
    SDK_SCANNER,
    MANIFEST_SCANNER,
    GOOGLE_SERVICES_SCANNER,
    NATIVE_SCANNER,
]

__all__ = ["DEFAULT_SCANNERS", "Scanner"]
