#!/usr/bin/env bash
# Autonomous CI setup + full pipeline test (no human-in-the-loop)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-${TARGET:-}}"
OUTPUT_DIR="${OUTPUT_DIR:-patch_artifacts}"
WINE_PREFIX="${WINE_PREFIX:-/tmp/defensive-audit-wine-prefix}"
CONFIG="${CONFIG:-config/default_config.json}"
SKIP_APT="${SKIP_APT:-0}"

log() { echo "[setup_ci] $*"; }

install_system_deps() {
  if [[ "$SKIP_APT" == "1" ]]; then
    log "SKIP_APT=1 — skipping apt packages"
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    log "apt-get unavailable — install Wine/Xvfb manually if needed"
    return 0
  fi
  log "Installing system dependencies (Wine, Xvfb, build tools)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    wine64 wine32 winbind \
    xvfb x11-utils \
    build-essential libyara-dev \
    ca-certificates curl git \
    >/dev/null
}

install_python_deps() {
  log "Installing Python package..."
  pip install -q --upgrade pip
  pip install -q -e ".[dev]" 2>/dev/null || pip install -q -e .
}

configure_wine_prefix() {
  if ! command -v wine >/dev/null 2>&1; then
    log "Wine not found — behavioral checks will SKIP"
    return 0
  fi
  export WINEPREFIX="$WINE_PREFIX"
  export WINEDEBUG="-all"
  export DISPLAY="${DISPLAY:-:99}"

  if ! pgrep -x Xvfb >/dev/null 2>&1; then
    log "Starting Xvfb on $DISPLAY..."
    Xvfb "$DISPLAY" -screen 0 1024x768x24 >/dev/null 2>&1 &
    sleep 1
  fi

  log "Initializing Wine prefix at $WINEPREFIX..."
  mkdir -p "$WINEPREFIX"
  wineboot --init >/dev/null 2>&1 || true
}

run_full_test() {
  if [[ -z "$TARGET" ]]; then
    log "Usage: $0 <target.exe>"
    log "  or:  TARGET=/path/to/target.exe $0"
    exit 1
  fi
  if [[ ! -f "$TARGET" ]]; then
    log "Target not found: $TARGET"
    exit 1
  fi

  log "Running unified pipeline + CI validation on $TARGET"
  python3 run_pipeline.py "$TARGET" \
    -o "$OUTPUT_DIR" \
    -c "$CONFIG" \
    --full-test \
    --wine-prefix "$WINE_PREFIX"
}

main() {
  log "Defensive Binary Audit — autonomous CI bootstrap"
  install_system_deps
  install_python_deps
  configure_wine_prefix
  run_full_test
  log "CI full test complete"
}

main "$@"
