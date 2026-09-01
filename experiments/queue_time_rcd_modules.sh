#!/bin/bash
# Serial queue: Time-RCD module matrix (one run at a time; device resources limited).
# Host adjustments (host CPU primary; GPU shared/OOM; huggingface.co unreachable):
#   - export CUDA_VISIBLE_DEVICES=""  -> --device auto resolves to cpu
#   - export HF_ENDPOINT=https://hf-mirror.com (checkpoints already cached after first fetch)
set -u
cd /hd_2t/lj/yzj_20260421/alg-models/eTrace-Diag || exit 1
export CUDA_VISIBLE_DEVICES=""
export HF_ENDPOINT=https://hf-mirror.com
mkdir -p results/time_rcd
run() {
  label=$1; mod=$2; shift 2
  echo "[$(date +%H:%M:%S)] START $label" >> results/time_rcd/queue.log
  uv run python -m experiments.baselines.time_rcd --data-root data/smd \
    --limit-machines 3 --device cpu --module "$mod" --experiment "$label" \
    --output "results/time_rcd/${label}.json" "$@" \
    > "results/time_rcd/${label}.stdout" 2> "results/time_rcd/${label}.progress"
  echo "[$(date +%H:%M:%S)] DONE $label rc=$?" >> results/time_rcd/queue.log
}
run base base
run median-k3 median-k3
run median-k5 median-k5
run ewma-a02 ewma-a02
run ewma-a05 ewma-a05
run cusum cusum
run temp-20 temp-20
run temp-05 temp-05
run quantile-0995 quantile-0995
run pot-gpd pot-gpd
run conformal-0005 conformal-0005
run unifusion-max unifusion-max
run unifusion-mean unifusion-mean
run multiscale multiscale
run overlap-half overlap-half
run fusion-robust-03 fusion-robust-03
run fusion-robust-05 fusion-robust-05
run cascade-g095 cascade-g095
run cascade-g099 cascade-g099
run channel-top-k8   base --channel-top-k 8
run channel-top-k16  base --channel-top-k 16
run channel-top-k24  base --channel-top-k 24
run batch-b4         base --batch-size 4
run batch-b8         base --batch-size 8
run autocast-bf16    base --autocast bf16
run autocast-fp16    base --autocast fp16
run ptq-int8-dynamic ptq-int8-dynamic
uv run python -m experiments.baselines.time_rcd_matrix \
    --dir results/time_rcd --out results/time_rcd/module_matrix.csv
echo "[$(date +%H:%M:%S)] QUEUE COMPLETE" >> results/time_rcd/queue.log
