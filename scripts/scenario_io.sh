#!/usr/bin/env bash
# I/O latency scenario: fio randrw under the collector, trigger DEEP.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/scenario_common.sh"

OUT="${OUT:-$ROOT/out_scenario_io}"
RUNTIME="${RUNTIME:-180}"
FIO_FILE="${FIO_FILE:-/tmp/fio-test.img}"
mkdir -p "$OUT"

start_harness

fio --name=randrw-test --filename="$FIO_FILE" --size=4G --rw=randrw --rwmixread=70 \
    --bs=4k --iodepth=64 --numjobs=4 --runtime="$RUNTIME" --time_based \
    --group_reporting &
FIO=$!
wait "$FIO"

sleep 5
stop_harness

S=$(latest_session); DB="$S/etrace.sqlite3"
require_nonempty "$DB" "etrace.sqlite3"
require_db_rows "$DB" "SELECT COUNT(*) FROM io_devices" "io_devices"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_iofile WHERE ordinal=1" "io_files"

# io_devices carries cumulative latency; the fio device must show non-zero lat_sum.
python3 - "$DB" <<'PY' || { echo "FAIL: no populated IO latency" >&2; exit 1; }
import sqlite3, sys
n = sqlite3.connect(sys.argv[1]).execute(
    "SELECT COUNT(*) FROM io_devices WHERE lat_sum > 0").fetchone()[0]
print("OK: populated IO latency" if n else "no")
sys.exit(0 if n else 1)
PY

python3 - "$DB" <<'PY' \
  && echo "OK: deep_iofile lists fio file" \
  || echo "WARN: fio file path not captured (open_path miss -> basename fallback)"
import sqlite3, sys
n = sqlite3.connect(sys.argv[1]).execute(
    "SELECT COUNT(*) FROM deep_iofile WHERE ordinal=1 "
    "AND (path LIKE '%fio%' OR path LIKE '/tmp/%')").fetchone()[0]
sys.exit(0 if n else 1)
PY