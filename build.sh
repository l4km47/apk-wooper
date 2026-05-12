#!/usr/bin/env bash
# APK Wooper Linux / macOS bootstrap.
#
# This script performs a full first-run setup using **Python 3.12**:
#
#   1. Locates a Python 3.12 interpreter (refuses anything else).
#   2. Creates / reuses a virtual environment named `.apkwooper`.
#   3. Generates / updates `.env` with all supported keys (idempotent).
#   4. Installs `requirements.txt`; optionally `requirements-optional.txt`.
#   5. Installs declared built-in plugin pip dependencies.
#   6. Bootstraps tools (JADX, Apktool, and the optional secret scanners
#      when their ENABLE_* flag is true in `.env`).
#   7. Sets up plugins (`plugins.json`, optionally clones MobSF).
#   8. Writes a `run.sh` runner that starts MobSF when ENABLE_MOBSF=true
#      and then launches `python -m apk_web`.
#
# Flags:
#   --force                 Regenerate SECRET_KEY and admin password even if
#                           they exist.
#   --with-tools            Force the tool bootstrap step (it also runs based
#                           on .env flags, so this is rarely needed).
#   --with-optional         Install requirements-optional.txt (apkid, etc.).
#   --with-mobsf            Also clone and run MobSF setup during build.
#   --skip-tools            Skip the tool bootstrap step (useful for CI).
#   --skip-plugins          Skip the plugin bootstrap step.
#   --no-auto-install-python
#                           Do not auto-install Python 3.12 when missing;
#                           fail with instructions instead.
#   --python BIN            Path to a Python 3.12 interpreter. Must report
#                           3.12.x.
#
# If Python 3.12 is not found on PATH the script attempts to install it via
# Homebrew (macOS) or apt/dnf (Linux) before continuing.
#
# Examples:
#   ./build.sh
#   ./build.sh --force
#   ./build.sh --with-optional --with-mobsf

set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT"

VENV_NAME=".apkwooper"
VENV_DIR="$ROOT/$VENV_NAME"
VENV_PY="$VENV_DIR/bin/python"

PYTHON_BIN=""
FORCE=0
WITH_TOOLS=0
WITH_OPTIONAL=0
WITH_MOBSF=0
SKIP_TOOLS=0
SKIP_PLUGINS=0
NO_AUTO_INSTALL=0
INIT_ARGS=()

# -------- Argument parsing --------
while [ $# -gt 0 ]; do
  case "$1" in
    --force)                  FORCE=1; INIT_ARGS+=(--force); shift ;;
    --with-tools)             WITH_TOOLS=1; shift ;;
    --with-optional)          WITH_OPTIONAL=1; shift ;;
    --with-mobsf)             WITH_MOBSF=1; shift ;;
    --skip-tools)             SKIP_TOOLS=1; shift ;;
    --skip-plugins)           SKIP_PLUGINS=1; shift ;;
    --no-auto-install-python) NO_AUTO_INSTALL=1; shift ;;
    --python)
      PYTHON_BIN="${2:?--python requires an argument}"
      shift 2 ;;
    -h|--help)
      sed -n '2,35p' "$0"
      exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2 ;;
  esac
done

# -------- Helper: check if a binary is Python 3.12.x --------
# Prints the version string on success, exits non-zero on failure.
is_python312() {
  local exe="$1"
  local ver
  ver="$("$exe" -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>/dev/null)" || return 1
  case "$ver" in
    3.12.*) echo "$ver"; return 0 ;;
    *)      return 1 ;;
  esac
}

# -------- Helper: find a Python 3.12 on PATH / known locations --------
find_python312() {
  for cand in python3.12 python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
      if is_python312 "$cand" >/dev/null 2>&1; then
        echo "$cand"
        return 0
      fi
    fi
  done

  # Homebrew (Apple Silicon and Intel)
  for brew_prefix in /opt/homebrew /usr/local; do
    local exe="$brew_prefix/bin/python3.12"
    if [ -x "$exe" ] && is_python312 "$exe" >/dev/null 2>&1; then
      echo "$exe"
      return 0
    fi
  done

  # pyenv
  if command -v pyenv >/dev/null 2>&1; then
    local pyenv_root
    pyenv_root="$(pyenv root 2>/dev/null || true)"
    if [ -n "$pyenv_root" ]; then
      local exe="$pyenv_root/versions/3.12/bin/python3.12"
      if [ -x "$exe" ] && is_python312 "$exe" >/dev/null 2>&1; then
        echo "$exe"
        return 0
      fi
    fi
  fi

  return 1
}

# -------- Helper: auto-install Python 3.12 --------
install_python312() {
  local os
  os="$(uname -s)"

  if [ "$os" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      echo ">> Installing Python 3.12 via Homebrew..."
      brew install python@3.12
      return 0
    else
      echo "WARNING: Homebrew not found. Install it from https://brew.sh/ then re-run," >&2
      echo "         or install Python 3.12 from https://www.python.org/downloads/ and" >&2
      echo "         pass --python /path/to/python3.12." >&2
      return 1
    fi
  fi

  # Linux — try common package managers in order.
  if command -v apt-get >/dev/null 2>&1; then
    echo ">> Installing Python 3.12 via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
    return 0
  fi

  if command -v dnf >/dev/null 2>&1; then
    echo ">> Installing Python 3.12 via dnf..."
    sudo dnf install -y python3.12
    return 0
  fi

  if command -v yum >/dev/null 2>&1; then
    echo ">> Installing Python 3.12 via yum..."
    sudo yum install -y python3.12
    return 0
  fi

  if command -v pacman >/dev/null 2>&1; then
    echo ">> Installing Python 3.12 via pacman..."
    sudo pacman -Sy --noconfirm python312
    return 0
  fi

  echo "ERROR: No supported package manager found (apt, dnf, yum, pacman, brew)." >&2
  echo "       Install Python 3.12 manually from https://www.python.org/downloads/" >&2
  echo "       and pass --python /path/to/python3.12." >&2
  return 1
}

# -------- Helper: run a venv python command; abort on failure --------
py() {
  "$VENV_PY" "$@"
  local rc=$?
  if [ $rc -ne 0 ]; then
    echo "ERROR: Command failed (exit $rc): $VENV_PY $*" >&2
    exit $rc
  fi
}

# -------- Helper: run a venv python command; warn on failure --------
py_safe() {
  "$VENV_PY" "$@" || {
    local rc=$?
    echo "WARNING: Command failed (exit $rc): $VENV_PY $*" >&2
    return $rc
  }
}

# -------- 1. Resolve Python 3.12 --------
if [ -n "$PYTHON_BIN" ]; then
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "ERROR: Python interpreter '$PYTHON_BIN' was not found." >&2
    exit 1
  fi
  VER="$(is_python312 "$PYTHON_BIN" 2>/dev/null)" || {
    echo "ERROR: '$PYTHON_BIN' is not Python 3.12 (got: $("$PYTHON_BIN" --version 2>&1))." >&2
    exit 1
  }
  echo ">> Using $PYTHON_BIN ($VER)"
  PY312="$PYTHON_BIN"
else
  PY312="$(find_python312 2>/dev/null)" || true
  if [ -n "$PY312" ]; then
    VER="$(is_python312 "$PY312")"
    echo ">> Using $PY312 ($VER)"
  else
    if [ "$NO_AUTO_INSTALL" -eq 1 ]; then
      cat >&2 <<'EOF'
ERROR: Python 3.12 was not found on PATH and --no-auto-install-python was supplied.

APK Wooper requires Python 3.12 specifically (some optional dependencies,
notably APKiD's yara-python-dex, do not yet have wheels for 3.13 / 3.14).

Install it via your package manager, e.g.:

  macOS:  brew install python@3.12
  Debian: sudo apt install python3.12 python3.12-venv
  Fedora: sudo dnf install python3.12

Then re-run this script, or pass --python /path/to/python3.12.
EOF
      exit 1
    fi

    echo ">> Python 3.12 not detected; bootstrapping it now."
    if ! install_python312; then
      exit 1
    fi

    # Re-search after install.
    PY312="$(find_python312 2>/dev/null)" || {
      echo "ERROR: Python 3.12 install reported success but the interpreter was not detected." >&2
      exit 1
    }
    VER="$(is_python312 "$PY312")"
    echo ">> Using $PY312 ($VER)"
  fi
fi

# -------- 2. Create .apkwooper venv --------
if [ ! -x "$VENV_PY" ]; then
  echo ">> Creating virtual environment at $VENV_DIR"
  "$PY312" -m venv "$VENV_DIR"
else
  echo ">> Reusing virtual environment at $VENV_DIR"
fi

# Verify the venv is actually 3.12 (guards against a stale venv from a
# different interpreter).
VENV_VER="$(is_python312 "$VENV_PY" 2>/dev/null)" || {
  echo "ERROR: Existing venv at $VENV_DIR is not Python 3.12. Delete it and rerun build." >&2
  exit 1
}

echo ">> Upgrading pip / setuptools / wheel"
py -m pip install --upgrade pip setuptools wheel

# -------- 3. Initialize .env --------
echo ">> Initializing .env"
py "$ROOT/scripts/init_env.py" "${INIT_ARGS[@]}"

# -------- 4. Install requirements --------
echo ">> Installing requirements.txt"
py -m pip install -r "$ROOT/requirements.txt"

if [ "$WITH_OPTIONAL" -eq 1 ]; then
  echo ">> Installing requirements-optional.txt"
  py_safe -m pip install -r "$ROOT/requirements-optional.txt" || \
    echo "WARNING: Some optional packages did not install. You can retry from Settings -> Analysis engine in the dashboard."
fi

# -------- 5. Install declared built-in plugin pip dependencies --------
echo ">> Installing declared built-in plugin pip dependencies"
py_safe "$ROOT/scripts/bootstrap_plugin_deps.py" || true

# -------- 6. Tool bootstrap --------
if [ "$SKIP_TOOLS" -eq 1 ]; then
  echo ">> Skipping tool bootstrap (--skip-tools)"
else
  echo ">> Bootstrapping tools (driven by .env ENABLE_* flags)"
  TOOL_ARGS=("$ROOT/scripts/bootstrap_all_tools.py")
  [ "$WITH_TOOLS" -eq 1 ] && TOOL_ARGS+=(--force)
  py_safe "${TOOL_ARGS[@]}" || true
fi

# -------- 7. Plugin bootstrap (plugins.json + optional MobSF) --------
if [ "$SKIP_PLUGINS" -eq 1 ]; then
  echo ">> Skipping plugin bootstrap (--skip-plugins)"
else
  echo ">> Bootstrapping plugins"
  PLUGIN_ARGS=("$ROOT/scripts/bootstrap_plugins.py")
  [ "$WITH_MOBSF" -eq 1 ] && PLUGIN_ARGS+=(--with-mobsf-setup)
  py_safe "${PLUGIN_ARGS[@]}" || true
fi

# -------- 8. Generate run.sh --------
echo ">> Writing run.sh"
py "$ROOT/scripts/write_run_sh.py"

cat <<EOF

Build complete.

Next steps:
  ./run.sh

Then open http://127.0.0.1:5000 and log in with the password printed above
(also saved to .admin_password.txt -- delete it after you store the password).
EOF