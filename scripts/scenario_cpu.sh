#!/usr/bin/env bash
# CPU anomaly scenario: stress-ng matrixprod under the collector, trigger DEEP.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/scenario_common.sh"

OUT="${OUT:-$ROOT/out_scenario_cpu}"
RUNTIME="${RUNTIME:-180}"
mkdir -p "$OUT"

start_harness

stress-ng --cpu 4 --cpu-method matrixprod --timeout "$RUNTIME" --metrics-brief &
STRESS=$!
wait "$STRESS"

sleep 5
stop_harness

S=$(latest_session)
require_nonempty "$S/targets.log" "targets.log"
require_nonempty "$S/base_host.jsonl" "base_host.jsonl"
require_nonempty "$S/deep/1/pre_series.jsonl" "pre_series.jsonl"
require_nonempty "$S/deep/1/post_series.jsonl" "post_series.jsonl"
require_nonempty "$S/deep/1/on_cpu.folded" "on_cpu.folded"
require_nonempty "$S/deep/1/summary.txt" "summary.txt"

grep -qi "matrixprod\|stress-ng" "$S/targets.log" \
  && echo "OK: stressor tid appears in targets.log" \
  || { echo "FAIL: stressor tid missing from targets.log" >&2; exit 1; }

grep -qi "matrix" "$S/deep/1/on_cpu.folded" \
  && echo "OK: on_cpu.folded contains matrixprod frames" \
  || echo "WARN: matrixprod frame not resolved (symbolization degrades to file+offset)"