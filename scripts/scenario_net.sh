#!/usr/bin/env bash
# Network end-to-end scenario: loopback TCP workload with the server tgid pinned
# as target, manual DEEP entry via USR1. Verifies base net_iface/net_stack rows
# and deep flow attribution/latency; drop/softirq tables are optional (empty ok).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/scenario_common.sh"

OUT="${OUT:-$ROOT/out_verify_net}"
RUNTIME="${RUNTIME:-15}"
mkdir -p "$OUT"

COL_PID=""; CLIENT_PID=""; SERVER_PID=""
port_file="$OUT/net_port.txt"; rm -f "$port_file"
cleanup() {
  sudo kill -INT "$COL_PID" 2>/dev/null || true
  kill "$SERVER_PID" "$CLIENT_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

python3 - "$port_file" <<'PYEOF' &
import socket, sys, time
port_file = sys.argv[1]
srv = socket.socket()
srv.bind(('127.0.0.1', 0))
srv.listen(16)
with open(port_file, 'w') as f:
    f.write(str(srv.getsockname()[1]))
def serve():
    while True:
        c, _ = srv.accept()
        try:
            while c.recv(65536):
                c.sendall(b'x' * 65536)
        except OSError:
            pass
        finally:
            c.close()
def client():
    port = open(port_file).read().strip()
    while True:
        try:
            c = socket.create_connection(('127.0.0.1', int(port)), timeout=5)
            c.sendall(b'y' * 262144)
            got = 0
            while got < 262144:
                d = c.recv(65536)
                if not d: break
                got += len(d)
            c.close()
        except OSError:
            pass
        time.sleep(0.05)
serve()
PYEOF
SERVER_PY=$!
for _ in $(seq 1 100); do [ -s "$port_file" ] && break; sleep 0.1; done
[ -s "$port_file" ] || { echo "server port never appeared" >&2; exit 1; }
SERVER_PID=$(pgrep -f "net_port.txt" | head -1 || true)
[ -n "$SERVER_PID" ] || SERVER_PID=$SERVER_PY
python3 - "$port_file" <<'PYEOF' &
import socket, sys, time
port_file = sys.argv[1]
port = open(port_file).read().strip()
while True:
    try:
        c = socket.create_connection(('127.0.0.1', int(port)), timeout=5)
        c.sendall(b'y' * 262144)
        got = 0
        while got < 262144:
            d = c.recv(65536)
            if not d: break
            got += len(d)
        c.close()
    except OSError:
        pass
    time.sleep(0.05)
PYEOF
CLIENT_PID=$!

export ETRACE_DIAG_MODEL_ANOMALY_URL=ws://127.0.0.1:9001/anomaly
export ETRACE_DIAG_MODEL_CAUSAL_URL=ws://127.0.0.1:9002/causal
export ETRACE_DIAG_OUTPUT_DIR="$OUT"
export ETRACE_DIAG_TARGETS_PINNED="$SERVER_PID"
sudo "$ROOT/build/etrace-diag" --config "$ROOT/config/default.json" &
COL_PID=$!
sleep 5
sudo kill -USR1 "$COL_PID"
sleep "$RUNTIME"
sudo kill -INT "$COL_PID"
wait "$COL_PID" 2>/dev/null || true

DB="$(latest_session)etrace.sqlite3"
require_db_rows "$DB" "SELECT COUNT(*) FROM (SELECT ifindex,MAX(rx_bytes)-MIN(rx_bytes) d FROM net_iface GROUP BY ifindex HAVING d>0)" "net_iface rx delta"
require_db_rows "$DB" "SELECT COUNT(*) FROM net_stack" "net_stack 行"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_net_flow WHERE tgid=(SELECT tgid FROM targets_log WHERE action='join' ORDER BY seq DESC LIMIT 1)" "deep_net_flow 目标归因"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_net_flow WHERE connect_latency_us IS NOT NULL" "connect_latency_us"
echo "optional: deep_net_drop=$(python3 - "$DB" <<'Q'
import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('SELECT COUNT(*) FROM deep_net_drop').fetchone()[0])
Q
) deep_net_softirq=$(python3 - "$DB" <<'Q'
import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('SELECT COUNT(*) FROM deep_net_softirq').fetchone()[0])
Q
)"
echo "scenario_net: PASS"
