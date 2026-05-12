"""Download external CLI tools used by APK Wooper into ``TOOLS_ROOT``.

Reads the repo's ``.env`` for flags, then ensures the binaries below exist:

* JADX + Apktool: always (the dashboard needs these for any decompile).
* Gitleaks if ``ENABLE_GITLEAKS=true``.
* TruffleHog if ``ENABLE_TRUFFLEHOG=true``.
* radare2 if ``ENABLE_RADARE2=true`` (Windows-only auto-install for now).

This script is invoked from ``build.ps1``. It is best-effort: a failure to
download an optional tool prints a warning but never aborts the whole build,
because the dashboard's Settings -> Analysis engine page can retry from the
UI later.

Flags:
    --force        Re-run ``ensure_*`` even if the tool already exists by
                   touching the relevant marker files (we leave existing
                   files in place; the helpers themselves are idempotent).
    --skip-core    Skip JADX/Apktool (useful when only refreshing scanners).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _ensure_repo_on_path() -> None:
    repo_str = str(REPO_ROOT)
    if repo_str not in sys.path:
        sys.path.insert(0, repo_str)


def _load_env() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError:
        return
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        load_dotenv(env_file)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _tools_root() -> Path:
    raw = os.environ.get("TOOLS_ROOT")
    if raw:
        return Path(raw)
    return REPO_ROOT / "tools"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--skip-core", action="store_true")
    args = parser.parse_args(argv)

    _ensure_repo_on_path()
    _load_env()

    logging.basicConfig(
        level=logging.INFO,
        format="[tools-bootstrap] %(message)s",
        stream=sys.stdout,
    )
    log = logging.getLogger("tools-bootstrap")

    try:
        from apk_web.tools_bootstrap import (
            ensure_decompiler_tools,
            ensure_gitleaks,
            ensure_radare2,
            ensure_trufflehog,
        )
    except Exception as exc:  # noqa: BLE001
        log.error("could not import apk_web.tools_bootstrap: %s", exc)
        return 1

    tools_root = _tools_root()
    log.info("TOOLS_ROOT=%s", tools_root)
    tools_root.mkdir(parents=True, exist_ok=True)

    failures = 0

    if args.skip_core:
        log.info("--skip-core: not touching JADX/Apktool")
    else:
        try:
            results = ensure_decompiler_tools(tools_root, logger=log)
            for name, downloaded in results.items():
                log.info("%s: %s", name, "downloaded" if downloaded else "already present")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.warning("decompiler tools failed: %s", exc)

    if _env_bool("ENABLE_GITLEAKS", False):
        try:
            path = ensure_gitleaks(tools_root, logger=log)
            log.info("gitleaks ok: %s", path)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.warning("gitleaks: %s", exc)
    else:
        log.info("ENABLE_GITLEAKS=false; skipping")

    if _env_bool("ENABLE_TRUFFLEHOG", False):
        try:
            path = ensure_trufflehog(tools_root, logger=log)
            log.info("trufflehog ok: %s", path)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.warning("trufflehog: %s", exc)
    else:
        log.info("ENABLE_TRUFFLEHOG=false; skipping")

    if _env_bool("ENABLE_RADARE2", False):
        try:
            path = ensure_radare2(tools_root, logger=log)
            log.info("radare2 ok: %s", path)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.warning("radare2: %s", exc)
    else:
        log.info("ENABLE_RADARE2=false; skipping")

    if failures:
        log.warning(
            "completed with %d warning(s); the dashboard can retry installs "
            "from Settings -> Analysis engine.",
            failures,
        )
    else:
        log.info("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
