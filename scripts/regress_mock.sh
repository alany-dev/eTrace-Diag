#!/usr/bin/env bash
# Collector regression against the mock model (no real ML): verifies BPF load,
# BASE ticks, DEEP trigger, evidence packaging, and diagnosis.json persistence.
#
#   usage: sudo ./scripts/regress_mock.sh [seconds]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_SECONDS="${1:-45}"
OUT="${OUT:-/tmp/etrace_regress}"
MODEL_PY="${MODEL_PY:-python3}"

rm -rf "$OUT"
mkdir -p "$OUT"

# mock model on the legacy two-port layout (collector URLs overridden below)
nohup "$MODEL_PY" -u "$ROOT/scripts/mock_model.py" --trigger-once \
  --anomaly-port 9001 --causal-port 9002 >"$OUT/mock.log" 2>&1 &
MOCK_PID=$!
trap 'kill $MOCK_PID 2>/dev/null || true' EXIT
sleep 2

ETRACE_DIAG_MODEL_ANOMALY_URL=ws://127.0.0.1:9001/anomaly \
ETRACE_DIAG_MODEL_CAUSAL_URL=ws://127.0.0.1:9002/causal \
ETRACE_DIAG_WINDOW_PRE_ANOMALY_SECONDS=10 \
ETRACE_DIAG_WINDOW_POST_ANOMALY_SECONDS=20 \
ETRACE_DIAG_OUTPUT_DIR="$OUT" \
"$ROOT/build/etrace-diag" --config "$ROOT/config/default.json" \
  --run-seconds "$RUN_SECONDS" >"$OUT/collector.log" 2>&1
echo "collector exit=$?"

S=$(ls -td "$OUT"/*/ | head -1)
DB="$S/etrace.sqlite3"
[ -f "$DB" ] || { echo "FAIL: no session db"; exit 1; }
python3 - "$DB" "$S" <<'EOF'
import json, sqlite3, sys
db, sess = sys.argv[1], sys.argv[2]
n = sqlite3.connect(db).execute("SELECT COUNT(*) FROM deep_episodes").fetchone()[0]
print(f"deep_episodes: {n}")
if n < 1:
    print("FAIL: mock never triggered DEEP"); sys.exit(1)
diag = sess + "/diagnosis.json"
try:
    d = json.load(open(diag))
except FileNotFoundError:
    print("FAIL: diagnosis.json missing"); sys.exit(1)
print(f"diagnosis ok={d.get('ok')} keys={list(d.keys())[:5]}")
sys.exit(0 if d.get("ok") else 1)
EOF
echo "regression passed"
