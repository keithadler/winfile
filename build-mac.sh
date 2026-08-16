#!/usr/bin/env bash
# Build + run Microsoft's Windows File Manager (winfile) on macOS.
# Cross-compiles to a Windows PE with mingw-w64, runs it under Wine.
# Prereqs (installed via Homebrew):  brew install mingw-w64 && brew install --cask wine-stable
set -euo pipefail
cd "$(dirname "$0")"

CC_BIN=x86_64-w64-mingw32-gcc
CXX_BIN=x86_64-w64-mingw32-g++
WINDRES_BIN=x86_64-w64-mingw32-windres

# --- Fix 1: backslash includes (lang\foo.rc / lang\foo.db) don't resolve on a
# case-sensitive Unix FS. Create backslash-named symlinks inside src/ so the
# literal include paths resolve, without touching any source file. ---
( cd src && for f in lang/*; do ln -sf "lang/$(basename "$f")" "lang\\$(basename "$f")"; done )

# --- Fix 2: GCC >=14 defaults to C23 and rejects 1990s implicit-int / implicit
# function decls as hard errors -> -std=gnu17 -fpermissive downgrades them.
# --- Fix 3: -Isrc/lang lets windres find nested same-dir resource includes.
# --- Fix 4: -static* so the .exe carries the MinGW/C++ runtime (no external
# libgcc_s_seh-1.dll / libstdc++-6.dll needed at runtime under Wine). ---
make \
  CC="$CC_BIN -std=gnu17 -fpermissive -Wno-implicit-int -Wno-implicit-function-declaration -Wno-int-conversion" \
  CXX="$CXX_BIN" \
  WINDRES="$WINDRES_BIN -Isrc/lang" \
  LDFLAGS="-static -static-libgcc -static-libstdc++" \
  "$@"

echo "Built: $(pwd)/winfile.exe"
file winfile.exe

if [ "${1:-}" = "run" ] || [ "${RUN:-}" = "1" ]; then
  export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-winfile}"
  export WINEDLLOVERRIDES="mscoree,mshtml="   # suppress mono/gecko install prompts
  wineboot --init >/dev/null 2>&1 || true
  cp winfile.exe "$WINEPREFIX/drive_c/winfile.exe"
  echo "Launching under Wine (prefix: $WINEPREFIX)..."
  ( cd "$WINEPREFIX/drive_c" && exec wine winfile.exe )
fi
