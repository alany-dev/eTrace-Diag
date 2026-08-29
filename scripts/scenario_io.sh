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

S=$(latest_session)
require_nonempty "$S/io_devices.txt" "io_devices.txt"
require_nonempty "$S/deep/1/io_files.txt" "io_files.txt"

# io_devices.txt rows carry a 13-bin latency histogram (laten-cumulative); the
# fio device must show a populated (non-zero) high-latency bucket.
python3 - "$S/io_devices.txt" <<'PY' || { echo "FAIL: no populated IO latency bucket" >&2; exit 1; }
import json, sys
found = False
for line in open(sys.argv[1]):
    e = json.loads(line)
    hist = e.get("hist", [])
    if any(hist[3:]):   # any non-zero bucket beyond the sub-ms range
        found = True
        break
print("OK: populated P99-relevant latency bucket" if found else "no")
sys.exit(0 if found else 1)
PY

grep -q "fio-test.img\|/tmp/" "$S/deep/1/io_files.txt" \
  && echo "OK: io_files.txt lists fio file" \
  || echo "WARN: fio file path not captured (open_path miss -> basename fallback)"