#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_SCRIPT="$ROOT_DIR/scripts/build-veksel"
BIN="${VEKSEL_DEV_BIN:-/tmp/veksel-dev-${USER:-user}/veksel}"
LOG="${VEKSEL_DEV_LOG:-/tmp/veksel-dev-${USER:-user}/dev-restart.log}"
SETTLE_SECONDS="${VEKSEL_DEV_SETTLE_SECONDS:-120}"
POLL_SECONDS="${VEKSEL_DEV_POLL_SECONDS:-1}"
STOP_GRACE_SECONDS="${VEKSEL_DEV_STOP_GRACE_SECONDS:-5}"
STOP_TIMEOUT_SECONDS="${VEKSEL_DEV_STOP_TIMEOUT_SECONDS:-15}"
CRASH_BACKOFF_SECONDS="${VEKSEL_DEV_CRASH_BACKOFF_SECONDS:-5}"
RESTART_HOLD_FILE="${VEKSEL_DEV_RESTART_HOLD_FILE:-$ROOT_DIR/.dev-no-restart}"

child_pid=""
crash_restart_at=0

mkdir -p "$(dirname "$LOG")"

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
  echo "$msg"
  echo "$msg" >> "$LOG"
}

cleanup() {
  if [[ -n "$child_pid" ]] && kill -0 "$child_pid" 2>/dev/null; then
    stop_veksel "$child_pid"
  fi
}

trap cleanup EXIT
trap 'exit 0' INT TERM

build_veksel() {
  "$BUILD_SCRIPT" "$BIN" >>"$LOG" 2>&1
}

launch_veksel() {
  cd "$ROOT_DIR"
  "$BIN" "$@" >>"$LOG" 2>&1 &
  child_pid="$!"
  log "launched veksel pid=$child_pid"
}

stop_veksel() {
  local pid="$1"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
    return 0
  fi
  log "stopping veksel pid=$pid for restart"
  kill -TERM "$pid" 2>/dev/null || true

  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited >= STOP_GRACE_SECONDS )); then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  if kill -0 "$pid" 2>/dev/null; then
    log "veksel pid=$pid did not stop after ${STOP_GRACE_SECONDS}s; killing"
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  child_pid=""
}

source_signature() {
  (
    cd "$ROOT_DIR"
    find cmd pkg \
      -type f \
      \( -name '*.go' -o -name '*.gohtml' -o -name '*.css' -o -name '*.js' -o -name '*.woff2' \) \
      ! -path '*/.git/*' \
      -printf '%p %T@ %s\n' 2>/dev/null
    find . \
      -maxdepth 1 \
      -type f \
      \( -name '*.go' -o -name '*.mod' -o -name '*.sum' \) \
      -printf '%p %T@ %s\n' 2>/dev/null
  ) | sort
}

wait_for_settle() {
  local previous
  local current
  local quiet

  previous="$(source_signature)"
  quiet=0
  while (( quiet < SETTLE_SECONDS )); do
    sleep 1
    current="$(source_signature)"
    if [[ "$current" == "$previous" ]]; then
      quiet=$((quiet + 1))
    else
      previous="$current"
      quiet=0
    fi
  done
}

if (( "$#" == 0 )); then
  set --
fi

log "building veksel..."
log "configuration at $ROOT_DIR/data/config.toml"
build_veksel
launch_veksel --data-dir "$ROOT_DIR/data" "$@"
last_signature="$(source_signature)"
restart_pending=0

while true; do
  sleep "$POLL_SECONDS"
  if [[ -n "$child_pid" ]] && ! kill -0 "$child_pid" 2>/dev/null; then
    wait "$child_pid" 2>/dev/null || true
    child_pid=""
    crash_restart_at=$(( $(date +%s) + CRASH_BACKOFF_SECONDS ))
    log "veksel exited unexpectedly; relaunch scheduled in ${CRASH_BACKOFF_SECONDS}s"
  fi

  if (( restart_pending == 1 )) && [[ ! -e "$RESTART_HOLD_FILE" ]]; then
    log "restart hold removed; building deferred changes..."
    if build_veksel; then
      if [[ -n "$child_pid" ]] && kill -0 "$child_pid" 2>/dev/null; then
        stop_veksel "$child_pid"
      fi
      launch_veksel --data-dir "$ROOT_DIR/data" "$@"
      crash_restart_at=0
      restart_pending=0
    else
      log "build failed; keeping current veksel process"
      restart_pending=0
    fi
  fi

  if [[ -z "$child_pid" ]] && (( crash_restart_at > 0 )) && [[ ! -e "$RESTART_HOLD_FILE" ]] && (( $(date +%s) >= crash_restart_at )); then
    launch_veksel --data-dir "$ROOT_DIR/data" "$@"
    crash_restart_at=0
  fi

  current_signature="$(source_signature)"
  if [[ "$current_signature" == "$last_signature" ]]; then
    continue
  fi

  log "changes detected; waiting ${SETTLE_SECONDS}s for code to settle..."
  wait_for_settle
  last_signature="$(source_signature)"

  if [[ -e "$RESTART_HOLD_FILE" ]]; then
    restart_pending=1
    log "restart deferred while $RESTART_HOLD_FILE exists"
    continue
  fi

  log "building veksel..."
  if build_veksel; then
    if [[ -n "$child_pid" ]] && kill -0 "$child_pid" 2>/dev/null; then
      stop_veksel "$child_pid"
    fi
    launch_veksel --data-dir "$ROOT_DIR/data" "$@"
    crash_restart_at=0
  else
    log "build failed; keeping current veksel process"
    log "build output:"
    tail -20 "$LOG" | while IFS= read -r line; do log "  $line"; done
  fi
done
