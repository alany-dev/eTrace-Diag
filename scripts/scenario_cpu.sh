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

S=$(latest_session); DB="$S/etrace.sqlite3"
require_nonempty "$DB" "etrace.sqlite3"
require_db_rows "$DB" "SELECT COUNT(*) FROM host" "host 行"
require_db_rows "$DB" "SELECT COUNT(*) FROM targets_log WHERE comm LIKE '%matrix%' OR comm LIKE '%stress%'" "stressor 在 targets_log"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_series WHERE ordinal=1 AND phase=0" "pre_series"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_series WHERE ordinal=1 AND phase=1" "post_series"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_folded WHERE ordinal=1 AND kind='on_cpu'" "on_cpu folded"
require_db_rows "$DB" "SELECT COUNT(*) FROM deep_episodes WHERE ordinal=1 AND summary_text IS NOT NULL" "summary"
python3 - "$DB" <<'EOF' \
  && echo "OK: matrixprod frames in on_cpu folded" \
  || echo "WARN: matrixprod frame not resolved (symbolization degrades to file+offset)"
import sqlite3, sys
db = sys.argv[1]
n = sqlite3.connect(db).execute("SELECT COUNT(*) FROM deep_folded WHERE ordinal=1 AND kind='on_cpu' AND frames LIKE '%matrix%'").fetchone()[0]
sys.exit(0 if n else 1)
EOF