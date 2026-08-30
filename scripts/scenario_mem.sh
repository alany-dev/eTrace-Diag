#!/usr/bin/env bash
# Memory-pressure scenario: stress-ng --vm under the collector.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/scenario_common.sh"

OUT="${OUT:-$ROOT/out_scenario_mem}"
RUNTIME="${RUNTIME:-180}"
mkdir -p "$OUT"

start_harness

stress-ng --vm 4 --vm-bytes 80% --vm-keep --timeout "$RUNTIME" --metrics-brief &
STRESS=$!
wait "$STRESS"

sleep 5
stop_harness

S=$(latest_session); DB="$S/etrace.sqlite3"
require_nonempty "$DB" "etrace.sqlite3"
require_db_rows "$DB" "SELECT COUNT(*) FROM memory_events" "memory_events"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_series WHERE ordinal=1 AND phase=0" "pre_series"

# faults.major should be non-zero in at least one pre/post snapshot.
python3 - "$DB" <<'PY' || exit 1
import sqlite3, sys
n = sqlite3.connect(sys.argv[1]).execute(
    "SELECT COUNT(*) FROM deep_series WHERE ordinal=1 AND pf_major > 0").fetchone()[0]
print("OK: major faults observed in snapshots" if n else "no major faults seen")
sys.exit(0 if n else 1)
PY

# kswapd/direct-reclaim transitions were logged.
python3 - "$DB" <<'PY' \
  && echo "OK: memory_events recorded reclaim/kswapd transitions" \
  || echo "WARN: no reclaim transitions this run (workload may not have paged)"
import sqlite3, sys
n = sqlite3.connect(sys.argv[1]).execute(
    "SELECT COUNT(*) FROM memory_events "
    "WHERE kswapd_active > 0 OR direct_reclaim > 0 OR nr_reclaimed > 0").fetchone()[0]
sys.exit(0 if n else 1)
PY