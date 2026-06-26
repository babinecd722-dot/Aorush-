#!/usr/bin/env bash
set -euo pipefail

export WINEPREFIX="${WINEPREFIX:-/tmp/defensive-audit-wine-prefix}"
export WINEDEBUG="${WINEDEBUG:--all}"
export DISPLAY="${DISPLAY:-:99}"

# Virtual framebuffer for headless Wine GUI checks
if ! pgrep -x Xvfb >/dev/null 2>&1; then
  Xvfb "$DISPLAY" -screen 0 1024x768x24 >/dev/null 2>&1 &
  sleep 1
fi

if [[ $# -eq 0 ]]; then
  exec bash
fi

if [[ "$1" == "--full-test" ]]; then
  shift
  TARGET="${1:?Usage: docker run ... --full-test <target.exe>}"
  shift || true
  exec /app/scripts/setup_ci.sh "$TARGET" "$@"
fi

exec "$@"
