#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TOOLS="$ROOT/tools"
JADX_ROOT="$TOOLS/jadx"

JADX_VERSION="1.5.5"
JADX_ZIP_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
APKTOOL_VERSION="2.11.1"
APKTOOL_JAR_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"

mkdir -p "$TOOLS"
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

echo "Downloading JADX ${JADX_VERSION} ..."
curl -fsSL "$JADX_ZIP_URL" -o "$TMP/jadx.zip"
unzip -q "$TMP/jadx.zip" -d "$TMP"
if [ -d "$TMP/lib" ]; then
  EXTRACTED="$TMP"
else
  EXTRACTED="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d -exec test -d {}/lib \; -print | head -n 1)"
fi
if [ -z "$EXTRACTED" ] || [ ! -d "$EXTRACTED/lib" ]; then
  echo "Could not find JADX root (folder with lib/) after unzip" >&2
  exit 1
fi
mkdir -p "$JADX_ROOT"
cp -R "$EXTRACTED"/. "$JADX_ROOT/"
echo "JADX installed under $JADX_ROOT"

echo "Downloading Apktool ${APKTOOL_VERSION} ..."
curl -fsSL "$APKTOOL_JAR_URL" -o "$TOOLS/apktool.jar"
echo "Apktool installed: $TOOLS/apktool.jar"

echo "Done."
