#!/bin/bash
# Native Apple Silicon build. No application code is generated through C.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$PROJECT_DIR/bin"
SRC="$PROJECT_DIR/src"
WORK="$PROJECT_DIR/.build"
MODE="${1:-all}"
die() { echo "error: $*" >&2; exit 1; }
case "$MODE" in all|build|test|unit|clean) ;; *) die "usage: $0 [all|build|test|clean]" ;; esac
if [ "$MODE" = clean ]; then
  rm -rf "$BIN" "$WORK"
  exit 0
fi
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || die "build on native Apple Silicon macOS (M1–M5)"
# Pin installed tooling, never a potentially modified sibling checkout.
if [ -z "${KCC:-}" ]; then
  if [ -x /opt/homebrew/opt/krypton/libexec/bootstrap/kcc_driver_macos_aarch64 ]; then
    export KRYPTON_ROOT="${KRYPTON_ROOT:-/opt/homebrew/opt/krypton/libexec}"
  else
    export KRYPTON_ROOT="${KRYPTON_ROOT:-/usr/local/krypton}"
  fi
  KCC="$KRYPTON_ROOT/bootstrap/kcc_driver_macos_aarch64"
else
  [ -n "${KRYPTON_ROOT:-}" ] || die "set KRYPTON_ROOT to match your custom KCC"
  export KRYPTON_ROOT
fi
[ -x "$KCC" ] || die "Krypton compiler missing: $KCC; install Krypton or set KCC and KRYPTON_ROOT"
VERSION="$("$KCC" --version 2>&1)"
case "$VERSION" in 'kcc version '*) ;; *) die "KCC is not the Krypton compiler: $KCC" ;; esac
[ -d "$KRYPTON_ROOT/stdlib" ] || die "missing stdlib in $KRYPTON_ROOT"
mkdir -p "$BIN" "$WORK"
MODULES="util model platform wifi scan capture crack report remote"
assemble() {
  local out="$1" extra="$2"
  : > "$out"
  for m in $MODULES; do
    sed -e '/^module /d' -e '/^import /d' "$SRC/$m.k" >> "$out"
    printf '\n' >> "$out"
  done
  sed -e '/^#!/d' -e '/^module /d' -e '/^import /d' "$extra" >> "$out"
}
compile() {
  local source="$1" output="$2" staged="$2.next" log="$2.log"
  rm -f "$staged"
  if ! "$KCC" "$source" -o "$staged" >"$log" 2>&1; then cat "$log" >&2; return 1; fi
  [ -x "$staged" ] || { cat "$log" >&2; return 1; }
  /usr/bin/lipo -verify_arch arm64 "$staged"
  /usr/bin/codesign --verify --strict "$staged"
  mv -f "$staged" "$output"
  rm -f "$log"
}
bundle() {
  local app="$WORK/Macgeddon.app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp "$BIN/macgeddon" "$app/Contents/MacOS/macgeddon"
  cp "$BIN/macgeddon-gui" "$app/Contents/MacOS/macgeddon-gui"
  cp "$PROJECT_DIR/LICENSE" "$app/Contents/Resources/LICENSE"
  cp "$PROJECT_DIR/README.md" "$app/Contents/Resources/README.md"
  cp "$PROJECT_DIR/scripts/Info.plist" "$app/Contents/Info.plist"
  /usr/bin/plutil -lint "$app/Contents/Info.plist" >/dev/null
  /usr/bin/codesign --force --sign - "$app" >/dev/null 2>&1
  /usr/bin/codesign --verify --deep --strict "$app"
  # Preserve the last working bundle until compilation and signing succeed.
  rm -rf "$BIN/Macgeddon.app.previous"
  if [ -d "$BIN/Macgeddon.app" ]; then mv "$BIN/Macgeddon.app" "$BIN/Macgeddon.app.previous"; fi
  mv "$app" "$BIN/Macgeddon.app"
  rm -rf "$BIN/Macgeddon.app.previous"
}
if [ "$MODE" = all ] || [ "$MODE" = build ]; then
  echo "Building with $VERSION ($KRYPTON_ROOT)"
  mkdir -p "$WORK/app"
  assemble "$WORK/app/run.k" "$SRC/macgeddon.ks"
  compile "$WORK/app/run.k" "$BIN/macgeddon"
  compile "$SRC/ui.k" "$BIN/macgeddon-gui"
  bundle
  echo "Built bin/macgeddon and bin/Macgeddon.app"
fi
if [ "$MODE" = all ] || [ "$MODE" = test ] || [ "$MODE" = unit ]; then
  mkdir -p "$WORK/tests"
  assemble "$WORK/tests/run.k" "$PROJECT_DIR/tests/test_macgeddon.k"
  compile "$WORK/tests/run.k" "$BIN/tests"
  (cd "$PROJECT_DIR" && "$BIN/tests")
fi
