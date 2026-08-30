#!/usr/bin/env bash
# Lock-contention scenario: stress-ng --mutex under the collector.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/scenario_common.sh"

OUT="${OUT:-$ROOT/out_scenario_lock}"
RUNTIME="${RUNTIME:-180}"
mkdir -p "$OUT"

start_harness

stress-ng --mutex 8 --timeout "$RUNTIME" --metrics-brief &
STRESS=$!
wait "$STRESS"

sleep 5
stop_harness

S=$(latest_session); DB="$S/etrace.sqlite3"
require_nonempty "$DB" "etrace.sqlite3"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_lock WHERE ordinal=1" "deep_lock"

# lock_st.waits must grow during the run.
python3 - "$DB" <<'PY' || exit 1
import sqlite3, sys
n = sqlite3.connect(sys.argv[1]).execute(
    "SELECT COUNT(*) FROM deep_series WHERE ordinal=1 AND lock_waits > 0").fetchone()[0]
print("OK: lock waits observed in snapshots" if n else "no lock waits seen")
sys.exit(0 if n else 1)
PY

# At least one hot lock address listed.
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_lock WHERE ordinal=1 AND addr LIKE '0x%'" "hot lock addr"