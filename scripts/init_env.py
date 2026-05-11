"""
First-run bootstrap for the repo-root `.env` file.

Generates:
  - SECRET_KEY              (64-byte url-safe random string)
  - DASHBOARD_PASSWORD_HASH (werkzeug scrypt hash of a random admin password)

Behavior:
  - If `.env` does not exist, it is created from `apk_web/.env.example`
    with the required secrets filled in.
  - If `.env` exists, only missing required keys are appended (idempotent).
  - With `--force`, existing required keys are overwritten with new values.

The generated plaintext admin password is printed once to stdout and
written to `.admin_password.txt` at the repo root (gitignored). Delete
that file once you have stored the password somewhere safe.
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env"
ENV_EXAMPLE = REPO_ROOT / "apk_web" / ".env.example"
PLAINTEXT_FILE = REPO_ROOT / ".admin_password.txt"

REQUIRED_KEYS = ("SECRET_KEY", "DASHBOARD_PASSWORD_HASH")


def _generate_secret_key() -> str:
    return secrets.token_urlsafe(64)


def _generate_admin_password() -> str:
    return secrets.token_urlsafe(18)


def _hash_password(password: str) -> str:
    try:
        from werkzeug.security import generate_password_hash
    except ImportError:
        sys.stderr.write(
            "ERROR: werkzeug is not installed. Run `pip install -r requirements.txt` "
            "first (build.sh / build.ps1 do this for you).\n"
        )
        sys.exit(2)
    return generate_password_hash(password, method="scrypt")


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


def _replace_or_append(text: str, key: str, value: str) -> str:
    pattern = re.compile(rf"(?m)^{re.escape(key)}=.*$")
    new_line = f"{key}={value}"
    if pattern.search(text):
        return pattern.sub(new_line, text)
    if text and not text.endswith("\n"):
        text += "\n"
    return text + new_line + "\n"


def _strip_password_lines(text: str) -> str:
    """Comment out any plaintext DASHBOARD_PASSWORD line we might inherit."""
    out_lines: list[str] = []
    for line in text.splitlines():
        if re.match(r"^\s*DASHBOARD_PASSWORD\s*=", line):
            out_lines.append("# " + line.lstrip())
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")


def _write_plaintext_password(password: str) -> None:
    PLAINTEXT_FILE.write_text(
        "# Auto-generated dashboard admin password.\n"
        "# Save this somewhere safe, then DELETE this file.\n"
        f"{password}\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate SECRET_KEY and admin password even if already set in .env.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print the generated admin password to stdout.",
    )
    args = parser.parse_args()

    if not ENV_EXAMPLE.exists():
        sys.stderr.write(f"ERROR: template not found: {ENV_EXAMPLE}\n")
        return 1

    existing = _read_env(ENV_FILE) if ENV_FILE.exists() else {}

    needs_secret = args.force or not existing.get("SECRET_KEY") or existing["SECRET_KEY"].startswith("change-me")
    needs_password = args.force or (
        not existing.get("DASHBOARD_PASSWORD_HASH")
        and not existing.get("DASHBOARD_PASSWORD")
    )

    if not needs_secret and not needs_password:
        print(f"OK: {ENV_FILE.name} already has SECRET_KEY and a dashboard password configured. "
              f"Use --force to regenerate.")
        return 0

    base_text = (
        ENV_FILE.read_text(encoding="utf-8")
        if ENV_FILE.exists()
        else ENV_EXAMPLE.read_text(encoding="utf-8")
    )

    new_password: str | None = None
    if needs_password:
        new_password = _generate_admin_password()
        password_hash = _hash_password(new_password)
        base_text = _strip_password_lines(base_text)
        base_text = _replace_or_append(base_text, "DASHBOARD_PASSWORD_HASH", password_hash)

    if needs_secret:
        base_text = _replace_or_append(base_text, "SECRET_KEY", _generate_secret_key())

    ENV_FILE.write_text(base_text, encoding="utf-8")
    try:
        ENV_FILE.chmod(0o600)
    except (OSError, NotImplementedError):
        pass

    print(f"Wrote {ENV_FILE}")

    if new_password is not None:
        _write_plaintext_password(new_password)
        try:
            PLAINTEXT_FILE.chmod(0o600)
        except (OSError, NotImplementedError):
            pass
        if not args.quiet:
            banner = "=" * 60
            print(banner)
            print("Dashboard admin password (shown ONCE):")
            print(f"    {new_password}")
            print(f"Also saved to: {PLAINTEXT_FILE}")
            print("Store it in a password manager, then delete that file.")
            print(banner)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
