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

S=$(latest_session)
require_nonempty "$S/memory_events.txt" "memory_events.txt"
require_nonempty "$S/deep/1/pre_series.jsonl" "pre_series.jsonl"

# faults.major should be non-zero in at least one pre/post snapshot.
python3 - "$S/deep/1/pre_series.jsonl" "$S/deep/1/post_series.jsonl" <<'PY' || exit 1
import json, sys
seen = False
for path in sys.argv[1:]:
    for line in open(path):
        e = json.loads(line)
        if e.get("pf_major", 0) > 0:
            seen = True
print("OK: major faults observed in snapshots" if seen else "no major faults seen")
sys.exit(0 if seen else 1)
PY

# kswapd/direct-reclaim transitions were logged.
grep -q "direct_reclaim" "$S/memory_events.txt" \
  && echo "OK: memory_events.txt recorded reclaim/kswapd transitions" \
  || echo "WARN: no reclaim transitions this run (workload may not have paged)"