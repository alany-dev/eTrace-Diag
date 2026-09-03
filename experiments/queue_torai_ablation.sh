#!/bin/bash
# TORAI ablation queue — strictly serial (one process at a time; no `&`,
# no `xargs -P`, no background concurrency). Device resources are limited.
#
# Screen (fixed 16 canonical masks x 4 suites, seed=7, variant=improved):
#   bash experiments/queue_torai_ablation.sh --screen
#   -> results/torai_ablation/screen/{suite}-{mask}-improved-s7.json
# Confirmation (deterministic manifest produced by --select-confirmation):
#   bash experiments/queue_torai_ablation.sh --confirm \
#       results/torai_ablation/screen-summary/confirmation.json
#   -> results/torai_ablation/confirm/{suite}-{mask}-{variant}-s{seed}.json
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p results/torai_ablation/screen results/torai_ablation/confirm
LOGF=results/torai_ablation/queue.log

MASKS=(none tail guided onset consensus \
       tail+guided tail+onset tail+consensus guided+onset guided+consensus onset+consensus \
       tail+guided+onset tail+guided+consensus tail+onset+consensus guided+onset+consensus \
       tail+guided+onset+consensus)

run_rcaeval() {  # $1=suite $2=mask $3=stage $4=seed $5=variant $6=outdir
  local suite=$1 mask=$2 stage=$3 seed=$4 variant=$5 outdir=$6
  local spec=${mask//+/,}  # canonical label -> comma-separated --modules input
  local extra=""
  [ "$suite" = "RE1" ] || extra="--logs --traces"
  local out="results/torai_ablation/$outdir/${suite}-${mask}-${variant}-s${seed}.json"
  if [ -f "$out" ]; then
    echo "[$(date +%H:%M:%S)] SKIP rcaeval $suite $mask $variant s$seed (exists)" >> "$LOGF"
    return
  fi
  echo "[$(date +%H:%M:%S)] START rcaeval $suite $mask $variant s$seed ($stage)" >> "$LOGF"
  uv run python -m experiments.run_torai_rcaeval \
    --suite "$suite" --variant "$variant" --modules "$spec" \
    --seed "$seed" --stage "$stage" \
    --output "$out" $extra \
    > "${out%.json}.stdout" \
    2> "${out%.json}.progress"
  local rc=$?
  echo "[$(date +%H:%M:%S)] DONE rcaeval $suite $mask $variant s$seed rc=$rc" >> "$LOGF"
}

run_aiops() {  # $1=mask $2=stage $3=seed $4=variant $5=outdir
  local mask=$1 stage=$2 seed=$3 variant=$4 outdir=$5
  local spec=${mask//+/,}
  local out="results/torai_ablation/$outdir/AIOPS-${mask}-${variant}-s${seed}.json"
  if [ -f "$out" ]; then
    echo "[$(date +%H:%M:%S)] SKIP aiops docker $mask $variant s$seed (exists)" >> "$LOGF"
    return
  fi
  echo "[$(date +%H:%M:%S)] START aiops docker $mask $variant s$seed ($stage)" >> "$LOGF"
  uv run python -m experiments.run_torai_aiops \
    --archive data/AIOps挑战赛2020预赛数据.zip --object docker --max-cols 50 \
    --variant "$variant" --modules "$spec" --seed "$seed" --stage "$stage" \
    --output "$out" \
    > "${out%.json}.stdout" \
    2> "${out%.json}.progress"
  local rc=$?
  echo "[$(date +%H:%M:%S)] DONE aiops docker $mask $variant s$seed rc=$rc" >> "$LOGF"
}


screen() {
  echo "[$(date +%H:%M:%S)] SCREEN QUEUE START" >> "$LOGF"
  for suite in RE1 RE2 RE3; do
    for mask in "${MASKS[@]}"; do
      run_rcaeval "$suite" "$mask" screen 7 improved screen
    done
  done
  for mask in "${MASKS[@]}"; do
    run_aiops "$mask" screen 7 improved screen
  done
  echo "[$(date +%H:%M:%S)] SCREEN QUEUE COMPLETE" >> "$LOGF"
}

confirm() {  # $1 = confirmation manifest JSON
  local manifest=$1
  while IFS='|' read -r suite modules variant seed; do
    if [ "$suite" = "AIOPS" ]; then
      run_aiops "$modules" confirm "$seed" "$variant" confirm
    else
      run_rcaeval "$suite" "$modules" confirm "$seed" "$variant" confirm
    fi
  done < <(uv run python - "$manifest" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
for suite in m["suites"]:
    for combo in m["combinations"]:
        for seed in m["seeds"]:
            print(f"{suite}|{combo['modules']}|{combo['variant']}|{seed}")
PY
)
  echo "[$(date +%H:%M:%S)] CONFIRM QUEUE COMPLETE" >> "$LOGF"
}

case "$1" in
  --screen) screen ;;
  --confirm) confirm "$2" ;;
  *) echo "usage: $0 --screen | --confirm <manifest.json>"; exit 2 ;;
esac
