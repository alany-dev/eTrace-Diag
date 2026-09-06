# WS 端到端联调场景：模型服务 + 采集器 + 轻量异常注入（缩减版）。
#
#   usage: sudo ./scripts/e2e_scenario.sh <cpu|io|mem|lock>   (需要 root：eBPF)
#
# 时间线（每场景约 3.5 分钟）：
#   t=0    启动模型 WS 服务（9000）与采集器；模型预热 60s（正常基线）
#   t=60   启动缩减版压力注入（90s）
#   t=150  压力停止，继续采集 40s（覆盖 post 窗口 + 因果推理）
#   t=190  干净退出；断言会话库 + diagnosis.json + 候选实体
#
# 环境：openKylin（setup_openkylin.sh 装好工具链与模型环境）。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCEN="${1:-cpu}"
case "$SCEN" in
  cpu|io|mem|lock) ;;
  *) echo "usage: $0 <cpu|io|mem|lock>" >&2; exit 2 ;;
esac

OUT="${OUT:-$ROOT/out_e2e_$SCEN}"
WARMUP=60
STRESS=90
POST=40
RUN_SECONDS=$((WARMUP + STRESS + POST + 10))
COLLECTOR="$ROOT/build/etrace-diag"
MODEL_DIR="${MODEL_DIR:-$ROOT/models}"
MODEL_PY="${MODEL_PY:-$MODEL_DIR/.venv/bin/python}"
MODEL_CFG="$MODEL_DIR/configs/e2e.yaml"

mkdir -p "$OUT"
[ -x "$COLLECTOR" ] || { echo "collector not built: $COLLECTOR" >&2; exit 1; }
[ -x "$MODEL_PY" ] || { echo "model env missing: $MODEL_PY (run setup_openkylin.sh)" >&2; exit 1; }

WS_PID=""
COL_PID=""
cleanup() {
  [ -n "$COL_PID" ] && sudo -n kill -INT "$COL_PID" 2>/dev/null || true
  [ -n "$WS_PID" ] && kill "$WS_PID" 2>/dev/null || true
  wait "$COL_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. model WS server (warmup/stride per models/configs/e2e.yaml)
(cd "$MODEL_DIR" && exec "$MODEL_PY" -m alg_models.ws_server \
  --config configs/e2e.yaml --host 127.0.0.1 --port 9000) >"$OUT/ws_server.log" 2>&1 &
WS_PID=$!
for _ in $(seq 1 30); do
  sleep 2
  if curl -s -m 3 -o /dev/null http://127.0.0.1:9000/docs; then break; fi
  kill -0 "$WS_PID" 2>/dev/null || break
done
if ! curl -s -m 3 -o /dev/null http://127.0.0.1:9000/docs; then
  echo "ws server not up; last log lines:" >&2
  tail -5 "$OUT/ws_server.log" >&2
  exit 1
fi

# 2. collector (BASE 全程；模型预热后打分，DEEP 由模型触发；post 窗口压到
#    30s 让 DEEP 在注入结束后自然 finalize 并完成因果推理)
ETRACE_DIAG_WINDOW_POST_ANOMALY_SECONDS=30 \
"$COLLECTOR" --config "$ROOT/config/default.json" --run-seconds "$RUN_SECONDS" \
  --output-dir "$OUT" >"$OUT/collector.log" 2>&1 &
COL_PID=$!

# 3. warmup window (normal baseline), then inject
sleep "$WARMUP"
echo "[$SCEN] injecting $STRESS s ..."
case "$SCEN" in
  cpu)
    stress-ng --cpu 2 --cpu-method matrixprod --timeout "${STRESS}s" --metrics-brief &
    STRESS_PID=$! ;;
  io)
    rm -f /tmp/fio-e2e.img
    fio --name=randrw-test --filename=/tmp/fio-e2e.img --size=1G --rw=randrw \
        --rwmixread=70 --bs=4k --iodepth=32 --numjobs=2 \
        --runtime=$STRESS --time_based --group_reporting &
    STRESS_PID=$! ;;
  mem)
    stress-ng --vm 2 --vm-bytes 40% --vm-keep --timeout "${STRESS}s" --metrics-brief &
    STRESS_PID=$! ;;
  lock)
    stress-ng --mutex 4 --timeout "${STRESS}s" --metrics-brief &
    STRESS_PID=$! ;;
esac
wait "$STRESS_PID"

# 4. post window: DEEP finalizes at the 30s deadline and runs the causal
#    analysis; poll for diagnosis.json before stopping anything.
sleep "$POST"
for _ in $(seq 1 24); do
  S_NOW=$(ls -td "$OUT"/*/ 2>/dev/null | head -1)
  [ -n "$S_NOW" ] && [ -f "$S_NOW/diagnosis.json" ] && break
  sleep 5
done
# stop the collector (its shutdown finalizes any remaining DEEP state), then
# the server. The causal request needs the server alive, so the collector
# goes first.
sudo -n kill -INT "$COL_PID" 2>/dev/null || true
wait "$COL_PID" 2>/dev/null || true
COL_PID=""
cleanup
trap - EXIT

# 5. assertions
S=$(ls -td "$OUT"/*/ 2>/dev/null | head -1)
[ -n "$S" ] || { echo "FAIL: no session dir" >&2; exit 1; }
DB="$S/etrace.sqlite3"
[ -f "$DB" ] || { echo "FAIL: no session db" >&2; exit 1; }
DIAG="$S/diagnosis.json"
[ -f "$DIAG" ] || { echo "FAIL: no diagnosis.json (causal reply missing)" >&2; exit 1; }

python3 - "$DB" "$DIAG" "$SCEN" <<'EOF'
import json, sqlite3, sys
db, diag, scen = sys.argv[1], sys.argv[2], sys.argv[3]
n_ep = sqlite3.connect(db).execute("SELECT COUNT(*) FROM deep_episodes").fetchone()[0]
if n_ep < 1:
    print("FAIL: no DEEP episode (model never triggered DEEP)"); sys.exit(1)
d = json.load(open(diag))
ok = d.get("ok")
report = d.get("report") or {}
cands = report.get("candidates") or []
if not ok:
    print(f"FAIL: causal ok=false ({d.get('abstained_reason')})"); sys.exit(1)
if not cands:
    print("FAIL: empty root-cause candidates"); sys.exit(1)
top = cands[0]
# entity sanity per scenario: cpu/mem/lock -> stress process; io -> proc or dev
ent = str(top.get("entity_id", ""))
valid = ent.startswith("proc") or ent.startswith("dev") or ent == "host"
if not valid:
    print(f"FAIL: unexpected top entity {ent!r}"); sys.exit(1)
print(f"OK: [{scen}] deep_episodes={n_ep} top={ent} rank={top.get('rank')} "
      f"score={top.get('score'):.3f} severity={top.get('severity')}")
print("     candidates:", [(c.get("entity_id"), c.get("rank")) for c in cands[:3]])
EOF
echo "e2e [$SCEN] passed"
