"""
First-run bootstrap for the repo-root `.env` file.

Generates:
  - SECRET_KEY              (64-byte url-safe random string)
  - DASHBOARD_PASSWORD_HASH (werkzeug scrypt hash of a random admin password)

Behavior:
  - If `.env` does not exist, it is created from `apk_web/.env.example`
    with the required secrets filled in.
  - If `.env` exists, the file is left untouched apart from:
      * required secrets that are missing or look like a placeholder
        ("change-me-...") are filled in, and
      * any keys from `apk_web/.env.example` that are not present in
        `.env` are appended (commented examples stay commented).
    Existing user values are never overwritten.
  - With `--force`, SECRET_KEY and the dashboard password are regenerated.

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


def _template_keys(text: str) -> list[str]:
    """Return ordered list of *uncommented* KEY entries from a template."""
    keys: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.partition("=")[0].strip()
        if key and key not in seen:
            keys.append(key)
            seen.add(key)
    return keys


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
    trailing = "\n" if text.endswith("\n") else ""
    return "\n".join(out_lines) + trailing


def _append_missing_keys(text: str, template_text: str, existing: dict[str, str]) -> tuple[str, list[str]]:
    """Append any uncommented template keys that are not already in `text`."""
    desired = _template_keys(template_text)
    missing = [k for k in desired if k not in existing]
    if not missing:
        return text, []

    if text and not text.endswith("\n"):
        text += "\n"

    additions: list[str] = []
    additions.append("")
    additions.append("# --- added by scripts/init_env.py (defaults from .env.example) ---")

    template_lines = template_text.splitlines()
    for key in missing:
        for raw in template_lines:
            stripped = raw.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            if stripped.partition("=")[0].strip() == key:
                additions.append(raw)
                break

    return text + "\n".join(additions) + "\n", missing


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

    template_text = ENV_EXAMPLE.read_text(encoding="utf-8")
    existing = _read_env(ENV_FILE) if ENV_FILE.exists() else {}

    base_text = (
        ENV_FILE.read_text(encoding="utf-8")
        if ENV_FILE.exists()
        else template_text
    )

    needs_secret = args.force or not existing.get("SECRET_KEY") or existing["SECRET_KEY"].startswith("change-me")
    needs_password = args.force or (
        not existing.get("DASHBOARD_PASSWORD_HASH")
        and not existing.get("DASHBOARD_PASSWORD")
    )

    new_password: str | None = None
    if needs_password:
        new_password = _generate_admin_password()
        password_hash = _hash_password(new_password)
        base_text = _strip_password_lines(base_text)
        base_text = _replace_or_append(base_text, "DASHBOARD_PASSWORD_HASH", password_hash)

    if needs_secret:
        base_text = _replace_or_append(base_text, "SECRET_KEY", _generate_secret_key())

    refreshed_existing = _read_env_text(base_text)
    base_text, appended = _append_missing_keys(base_text, template_text, refreshed_existing)

    ENV_FILE.write_text(base_text, encoding="utf-8")
    try:
        ENV_FILE.chmod(0o600)
    except (OSError, NotImplementedError):
        pass

    if needs_secret or needs_password or appended:
        print(f"Wrote {ENV_FILE}")
    else:
        print(f"OK: {ENV_FILE.name} is up to date.")

    if appended:
        print(f"Appended missing config keys: {', '.join(appended)}")

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


def _read_env_text(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines out of an in-memory env file body."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


if __name__ == "__main__":
    raise SystemExit(main())
