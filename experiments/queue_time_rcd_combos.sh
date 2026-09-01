#!/bin/bash
# Serial queue: Time-RCD combination stage (accuracy winners, two-module chains).
# User directive 2026-08-31: combine winning modules to beat base FIRST; quantization deferred.
# Strictly one run at a time; CPU only; no parallel constructs.
set -u
cd /hd_2t/lj/yzj_20260421/alg-models/eTrace-Diag || exit 1
export CUDA_VISIBLE_DEVICES=""
export HF_ENDPOINT=https://hf-mirror.com
mkdir -p results/time_rcd
run() {
  label=$1; shift
  echo "[$(date +%H:%M:%S)] START $label" >> results/time_rcd/queue.log
  uv run python -m experiments.baselines.time_rcd --data-root data/smd \
    --limit-machines 3 --device cpu --module "$label" --experiment "$label" \
    --output "results/time_rcd/${label}.json" \
    > "results/time_rcd/${label}.stdout" 2> "results/time_rcd/${label}.progress"
  echo "[$(date +%H:%M:%S)] DONE $label rc=$?" >> results/time_rcd/queue.log
}
run combo-med5-ewma02
run combo-ewma02-fusion03
run combo-med5-fusion03
run combo-fusion03-med5
run combo-temp20-ewma02
run combo-ewma05-med5
run combo-ewma02-q0995
uv run python -m experiments.baselines.time_rcd_matrix \
    --dir results/time_rcd --out results/time_rcd/module_matrix.csv
echo "[$(date +%H:%M:%S)] COMBO QUEUE COMPLETE" >> results/time_rcd/queue.log
