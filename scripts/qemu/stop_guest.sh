#!/usr/bin/env bash
# Stop one guest (qemu process) — the rootfs/image persist for re-runs.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ARCH="${1:-}"
if [ -z "$ARCH" ]; then
  for a in $ALL_ARCHES; do "$0" "$a"; done
  exit 0
fi
PIDF=$(arch_pidfile "$ARCH")
if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  kill "$(cat "$PIDF")" && echo "[$ARCH] stopped"
else
  echo "[$ARCH] not running"
fi
