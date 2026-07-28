#!/usr/bin/env bash
# Fetch the CodeQL bundle (CLI + codeql/<lang>-all library packs) at a pinned version
# and verify its SHA-256. The repo-scan taint SAST's CodeQL engine -- wired in by the
# stacked adapter -- uses it for cross-file Go/TS/Python taint. Not vendored: downloaded
# here and gitignored. On unsupported platforms, install the CodeQL bundle yourself and
# set MCPXRAY_CODEQL_BIN to its `codeql` binary.
set -euo pipefail

CODEQL_BUNDLE_TAG="codeql-bundle-v2.25.6"
CODEQL_VERSION="${CODEQL_BUNDLE_TAG#codeql-bundle-v}" # derive so the check/log can't drift
REPO="github/codeql-action"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
mkdir -p bin

# CodeQL ships one 64-bit bundle per OS (osx64 is universal; there is no arm64 Linux
# bundle). Windows works under git-bash/MSYS where uname reports MINGW/MSYS/CYGWIN.
OS="$(uname -s)"
ARCH="$(uname -m)"
EXE="codeql"
case "$OS" in
  Linux)
    [[ "$ARCH" == "x86_64" ]] || { echo "[!] no pinned CodeQL bundle for Linux/${ARCH}." >&2; exit 1; }
    ASSET="codeql-bundle-linux64.tar.gz"
    EXPECTED_SHA="55c5a760f8a98d882ce452f69c427116a034d91450c627bef717d4acd896632c"
    ;;
  Darwin)
    ASSET="codeql-bundle-osx64.tar.gz"
    EXPECTED_SHA="29ffd26c5a3a455625dde92886a92514812987d0f70c46fd457db96516f2243b"
    ;;
  MINGW* | MSYS* | CYGWIN*)
    ASSET="codeql-bundle-win64.tar.gz"
    EXPECTED_SHA="6ce0338cd58a104a9d4e4a11d7fd1711c43bd7fb43731b451dfa8fba5b0ecd2c"
    EXE="codeql.exe"
    ;;
  *)
    echo "[!] no pinned CodeQL bundle for ${OS}/${ARCH}." >&2
    echo "    Install the CodeQL bundle manually and set MCPXRAY_CODEQL_BIN to its codeql binary." >&2
    exit 1
    ;;
esac

# Linux/git-bash ship sha256sum; macOS ships `shasum -a 256`. Support both.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

DEST_DIR="bin/codeql-bundle"
CODEQL_EXE="$DEST_DIR/codeql/${EXE}"
TARBALL="bin/${ASSET}"
URL="https://github.com/${REPO}/releases/download/${CODEQL_BUNDLE_TAG}/${ASSET}"

CACHED_VERSION="$([[ -x "$CODEQL_EXE" ]] && "$CODEQL_EXE" version --format=terse 2>/dev/null || true)"
if [[ -x "$CODEQL_EXE" && "${CACHED_VERSION//[$'\r\n']/}" == "$CODEQL_VERSION" ]]; then
  echo "[*] already installed: CodeQL $CODEQL_VERSION at $CODEQL_EXE"
  exit 0
fi

echo "[*] downloading $URL"
curl -fsSL "$URL" -o "$TARBALL"
ACTUAL="$(sha256 "$TARBALL")"
if [[ "$ACTUAL" != "$EXPECTED_SHA" ]]; then
  echo "[FATAL] SHA-256 mismatch" >&2
  echo "  expected: $EXPECTED_SHA" >&2
  echo "  actual:   $ACTUAL" >&2
  rm -f "$TARBALL"
  exit 1
fi
echo "[*] SHA-256 verified; extracting to $DEST_DIR"
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
tar -xzf "$TARBALL" -C "$DEST_DIR"
rm -f "$TARBALL"
[[ -x "$CODEQL_EXE" ]] || { echo "[FATAL] $CODEQL_EXE missing after extract" >&2; exit 1; }
# Assert the freshly extracted binary actually runs (nonzero exit fails here, not just a
# bad version string) and reports the pinned version, so a truncated or broken download
# can't exit 0. stderr stays visible so the binary's real error surfaces; strip CR so a
# CRLF version from codeql.exe under git-bash doesn't spuriously mismatch.
if ! GOT_VERSION="$("$CODEQL_EXE" version --format=terse)"; then
  echo "[FATAL] extracted CodeQL at $CODEQL_EXE failed to report a version" >&2
  exit 1
fi
GOT_VERSION="${GOT_VERSION//[$'\r\n']/}"
if [[ "$GOT_VERSION" != "$CODEQL_VERSION" ]]; then
  echo "[FATAL] extracted CodeQL reports version '${GOT_VERSION:-<none>}', expected $CODEQL_VERSION" >&2
  exit 1
fi
echo "[*] installed CodeQL $GOT_VERSION at $HERE/$CODEQL_EXE"
