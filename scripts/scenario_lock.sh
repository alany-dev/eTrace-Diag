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

S=$(latest_session)
require_nonempty "$S/deep/1/lock_contention.txt" "lock_contention.txt"

# lock_st.waits must grow during the run.
python3 - "$S/deep/1/pre_series.jsonl" "$S/deep/1/post_series.jsonl" <<'PY' || exit 1
import json, sys
seen = False
for path in sys.argv[1:]:
    for line in open(path):
        e = json.loads(line)
        if e.get("lock_waits", 0) > 0:
            seen = True
print("OK: lock waits observed in snapshots" if seen else "no lock waits seen")
sys.exit(0 if seen else 1)
PY

# At least one hot lock address listed.
grep -q "0x" "$S/deep/1/lock_contention.txt" \
  && echo "OK: lock_contention.txt lists >=1 hot lock_addr" \
  || { echo "FAIL: no hot lock address listed" >&2; exit 1; }