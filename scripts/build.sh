#!/bin/bash
# scripts/build.sh — build macgeddon (Krypton 2.4.x, macOS arm64).
#
# The Krypton compiler installs as /usr/local/bin/kcc, but macOS ships a
# DIFFERENT /usr/bin/kcc (Heimdal Kerberos) that wins on a default PATH, so
# every invocation here uses an absolute path.
#
# Krypton resolves `import "k:..."` for the stdlib, and a relative import
# carries its extension (`import "util.k"`). macgeddon keeps its modules as
# separate, readable sources and assembles them into ONE translation unit in
# dependency order before compiling:
#   util -> model -> platform -> wifi -> scan -> capture -> crack -> report
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/bin"
SRC="$ROOT/src"
WORK="$ROOT/.build"
KCC="${KCC:-/usr/local/bin/kcc}"

MODULES="util model platform wifi scan capture crack report remote"

die() { echo "error: $*" >&2; exit 1; }

[ -x "$KCC" ] || die "Krypton compiler not found at $KCC (set KCC=/path/to/kcc)"

mode="${1:-all}"
case "$mode" in
  all|build|test|clean|unit) ;;
  *) die "usage: $0 [all|build|test|clean]" ;;
esac

if [ "$mode" = "clean" ]; then
  rm -rf "$BIN" "$WORK"
  echo "cleaned $BIN and $WORK"
  exit 0
fi

mkdir -p "$BIN" "$WORK"

# assemble <outfile> <extra.k> — modules in order, then the entry file.
assemble() {
  local out="$1" extra="$2"
  : > "$out"
  for m in $MODULES; do
    sed -e '/^module /d' -e '/^import /d' "$SRC/$m.k" >> "$out"
    printf '\n' >> "$out"
  done
  if [ -n "$extra" ]; then
    sed -e '/^#!\/usr\/env kr/d' -e '/^import /d' "$extra" >> "$out"
  fi
}

# compile <src> <out> — uses -o when accepted, otherwise renames the
# compiler's default output. Never a silent failure.
#
# The output is REMOVED first and success means "kcc produced it again":
# checking only that $out is executable passed stale binaries off as fresh
# builds (kcc prints "IR emission failed" yet the old binary still sat at
# $out, so a broken source reported "cli -> bin/macgeddon" and exit 0).
# kcc's stdout is captured to a log rather than piped, because filtering
# through grep would mask kcc's exit status.
compile() {
  local src="$1" out="$2"
  local dir; dir="$(dirname "$src")"
  local base; base="$(basename "$src" .k)"
  rm -f "$out"
  local log; log="$(mktemp)"
  local st=0
  "$KCC" "$src" -o "$out" >"$log" 2>&1 || st=$?
  grep -v 'macho_arm64_self' "$log" >&2 || true
  rm -f "$log"
  if [ "$st" -eq 0 ] && [ -x "$out" ]; then return 0; fi
  # fallback: kcc builds that ignore -o write their default output name
  rm -f "$dir/a.out" "$dir/$base"
  ( cd "$dir" && "$KCC" "$(basename "$src")" >/dev/null 2>&1 )
  for cand in "$dir/a.out" "$dir/$base" "$dir/bin"; do
    if [ -f "$cand" ] && [ -x "$cand" ]; then
      mv "$cand" "$out" && return 0
    fi
  done
  return 1
}

rc=0
if [ "$mode" = "all" ] || [ "$mode" = "build" ]; then
  echo "macgeddon build — $("$KCC" --version 2>&1 | head -1)"
  mkdir -p "$WORK/app"
  assemble "$WORK/app/run.k" "$SRC/macgeddon.ks"
  if compile "$WORK/app/run.k" "$BIN/macgeddon"; then
    echo "  cli  -> bin/macgeddon ($(wc -l < "$WORK/app/run.k" | tr -d ' ') lines)"
  else
    echo "  FAILED: cli" >&2; rc=1
  fi
  if compile "$SRC/ui.k" "$BIN/macgeddon-gui"; then
    echo "  gui  -> bin/macgeddon-gui"
  else
    echo "  FAILED: gui (objective-k/cocoa)" >&2; rc=1
  fi
fi

if [ "$mode" = "all" ] || [ "$mode" = "test" ] || [ "$mode" = "unit" ]; then
  echo "tests"
  mkdir -p "$WORK/tests"
  assemble "$WORK/tests/run.k" "$ROOT/tests/test_macgeddon.k"
  if compile "$WORK/tests/run.k" "$BIN/tests"; then
    if ( cd "$ROOT" && "$BIN/tests" ); then
      echo "  tests ok"
    else
      echo "  TESTS FAILED" >&2; rc=1
    fi
  else
    echo "  FAILED: tests" >&2; rc=1
  fi
fi

exit "$rc"
