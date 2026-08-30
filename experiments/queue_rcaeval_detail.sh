#!/bin/bash
# Serial queue: RCAeval per-case detail runs (one at a time, no concurrency).
set -u
cd /hd_2t/lj/yzj_20260421/alg-models/eTrace-Diag || exit 1
mkdir -p results/rcaeval
run() {
  suite=$1; variant=$2; extra=$3
  echo "[$(date +%H:%M:%S)] START $suite $variant" >> results/rcaeval/queue.log
  uv run python -m experiments.run_torai_rcaeval --suite "$suite" --variant "$variant" $extra \
    --out-cases "results/rcaeval/${suite}-${variant}-cases.json" \
    > "results/rcaeval/${suite}-${variant}.json" 2> "results/rcaeval/${suite}-${variant}.progress"
  echo "[$(date +%H:%M:%S)] DONE $suite $variant rc=$?" >> results/rcaeval/queue.log
}
run RE1 faithful ""
run RE1 improved ""
run RE2 faithful "--logs --traces"
run RE2 improved "--logs --traces"
run RE3 faithful "--logs --traces"
run RE3 improved "--logs --traces"
echo "[$(date +%H:%M:%S)] QUEUE COMPLETE" >> results/rcaeval/queue.log
