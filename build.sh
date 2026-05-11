#!/usr/bin/env bash
# First-run bootstrap for apk-wooper (Linux / macOS).
# - Creates .venv, installs requirements, generates .env with SECRET_KEY
#   and a hashed dashboard admin password.
#
# Flags:
#   --force        Regenerate SECRET_KEY and admin password even if .env already has them.
#   --with-tools   Also run scripts/bootstrap_tools.sh to fetch JADX + Apktool now
#                  (otherwise the app downloads them on first start).
#   --no-venv      Use the system `python3` directly instead of creating .venv.
#   --python BIN   Use a specific Python interpreter (default: python3).

set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT"

PYTHON_BIN="python3"
USE_VENV=1
FORCE=0
WITH_TOOLS=0
INIT_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --force)      FORCE=1; INIT_ARGS+=(--force); shift ;;
    --with-tools) WITH_TOOLS=1; shift ;;
    --no-venv)    USE_VENV=0; shift ;;
    --python)     PYTHON_BIN="${2:?--python requires an argument}"; shift 2 ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2 ;;
  esac
done

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: '$PYTHON_BIN' not found on PATH. Install Python 3.10+ or pass --python /path/to/python." >&2
  exit 1
fi

if [ "$USE_VENV" -eq 1 ]; then
  VENV_DIR="$ROOT/.venv"
  if [ ! -x "$VENV_DIR/bin/python" ]; then
    echo ">> Creating virtual environment at $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi
  PY="$VENV_DIR/bin/python"
else
  PY="$PYTHON_BIN"
fi

echo ">> Upgrading pip"
"$PY" -m pip install --upgrade pip >/dev/null

echo ">> Installing requirements"
"$PY" -m pip install -r "$ROOT/requirements.txt"

echo ">> Initializing .env (secrets + admin password)"
"$PY" "$ROOT/scripts/init_env.py" "${INIT_ARGS[@]}"

if [ "$WITH_TOOLS" -eq 1 ]; then
  echo ">> Bootstrapping JADX + Apktool"
  sh "$ROOT/scripts/bootstrap_tools.sh"
fi

cat <<EOF

Build complete.

Next steps:
  $( [ "$USE_VENV" -eq 1 ] && echo "source .venv/bin/activate" )
  python -m apk_web

Then open http://127.0.0.1:5000 and log in with the password printed above
(also saved to .admin_password.txt -- delete it after you store the password).
EOF
