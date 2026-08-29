#!/usr/bin/env bash
# Run the collector. Forwarded args override config (e.g. --run-seconds 60).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Must be root or hold CAP_BPF + CAP_PERFMON (else the eBPF load fails fast).
exec sudo --preserve-env "$ROOT/build/etrace-diag" \
  --config "$ROOT/config/default.json" "$@"