#!/usr/bin/env bash
# Common helpers for scenario scripts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Start mock model (trigger-once) + collector; echo pids via globals.
start_harness() {
  python3 "$ROOT/scripts/mock_model.py" --trigger-once &
  MOCK_PID=$!
  sleep 1
  export ETRACE_DIAG_MODEL_ANOMALY_URL=ws://127.0.0.1:9001/anomaly
  export ETRACE_DIAG_MODEL_CAUSAL_URL=ws://127.0.0.1:9002/causal
  export ETRACE_DIAG_OUTPUT_DIR="$OUT"
  sudo "$ROOT/build/etrace-diag" --config "$ROOT/config/default.json" &
  COL_PID=$!
  sleep 5  # allow load + DEEP entry
}

stop_harness() {
  sudo kill -INT "$COL_PID" 2>/dev/null || true
  wait "$COL_PID" 2>/dev/null || true
  kill "$MOCK_PID" 2>/dev/null || true
}

latest_session() {
  ls -td "$OUT"/*/ 2>/dev/null | head -1
}

# Assert $1 exists and is non-empty; $2 is a description.
require_nonempty() {
  local f="$1" desc="$2"
  if [ -s "$f" ]; then
    echo "OK: $desc ($f)"
  else
    echo "FAIL: $desc ($f) missing/empty" >&2
    exit 1
  fi
}