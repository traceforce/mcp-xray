#!/usr/bin/env bash
# Fetch the OpenGrep engine (LGPL-2.1) at a pinned version and verify its SHA-256.
# The taint SAST in `repo-scan` uses it. The binary is not vendored; it is
# downloaded here and gitignored. On unsupported platforms, install opengrep
# yourself and point MCPXRAY_OPENGREP_BIN at it.
set -euo pipefail

OPENGREP_VERSION="v1.22.0"
REPO="opengrep/opengrep"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
mkdir -p bin

# Windows works under git-bash/MSYS where uname reports MINGW/MSYS/CYGWIN, same
# detection install_codeql.sh already relies on. EXE picks the opengrep.exe name
# there so it lands where the Go resolver (opengrepExe() in taint/opengrep.go)
# looks for it next to the mcpxray binary.
EXE="opengrep"

OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}/${ARCH}" in
  Linux/x86_64)
    ASSET="opengrep_manylinux_x86"
    EXPECTED="45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319"
    ;;
  Linux/aarch64 | Linux/arm64)
    ASSET="opengrep_manylinux_aarch64"
    EXPECTED="8df71670e20336646687c6f4ddf9b4532f1a7fcd8a8ea7bfa4ea46747f61e088"
    ;;
  Darwin/arm64)
    ASSET="opengrep_osx_arm64"
    EXPECTED="6105ab78eca041fcb9f83055939088ba8f96a6cb66683ceced39652938b217ce"
    ;;
  Darwin/x86_64)
    ASSET="opengrep_osx_x86"
    EXPECTED="e9733c7ac4ad16ac5bbbcbff0264478c7b524d6750f29c847f93aacee3315d2b"
    ;;
  MINGW*/x86_64 | MSYS*/x86_64 | CYGWIN*/x86_64)
    ASSET="opengrep_windows_x86.exe"
    EXPECTED="f4f91b0a6268318df1dbb63e11f0ba2e9fdc355fa27d1de8fe9abf6c8a8e9efa"
    EXE="opengrep.exe"
    ;;
  *)
    echo "[!] no pinned OpenGrep asset for ${OS}/${ARCH}." >&2
    echo "    Install opengrep manually and set MCPXRAY_OPENGREP_BIN to its path." >&2
    exit 1
    ;;
esac
DEST="bin/${EXE}"

# Linux/git-bash ship sha256sum; macOS ships `shasum -a 256`. Support both so
# every pinned asset above actually verifies.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [[ -x "$DEST" ]] && [[ "$(sha256 "$DEST")" == "$EXPECTED" ]]; then
  echo "[*] already installed and hash-verified: $("$DEST" --version 2>/dev/null | head -1)"
  exit 0
fi

URL="https://github.com/${REPO}/releases/download/${OPENGREP_VERSION}/${ASSET}"
echo "[*] downloading $URL"
curl -fsSL "$URL" -o "$DEST"
chmod +x "$DEST"

ACTUAL="$(sha256 "$DEST")"
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  echo "[FATAL] SHA-256 mismatch" >&2
  echo "  expected: $EXPECTED" >&2
  echo "  actual:   $ACTUAL" >&2
  rm -f "$DEST"
  exit 1
fi
echo "[*] SHA-256 verified; installed $("$DEST" --version 2>/dev/null | head -1) at $HERE/$DEST"
