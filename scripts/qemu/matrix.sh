#!/usr/bin/env bash
# Cross-arch acceptance matrix: prepare -> boot -> verify for every arch.
#
#   sudo ./matrix.sh [arch ...]      (default: $ALL_ARCHES = x86_64 arm64 loong64 riscv64)
#
# Results append to $QEMU_DATA/matrix-results.txt.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ARCHES="${*:-$ALL_ARCHES}"
RESULT="$QEMU_DATA/matrix-results.txt"
: > "$RESULT"

for ARCH in $ARCHES; do
  echo "===================== $ARCH ====================="
  START=$(date +%s)
  STATUS=FAIL
  REASON=""
  if ./prepare_guest.sh "$ARCH" >"$QEMU_DATA/$ARCH.prepare.log" 2>&1; then
    if ./boot_guest.sh "$ARCH" >"$QEMU_DATA/$ARCH.boot.log" 2>&1; then
      sleep 15  # let the guest settle (systemd + sshd)
      if ./verify_guest.sh "$ARCH" >"$QEMU_DATA/$ARCH.verify.log" 2>&1; then
        STATUS=PASS
      else
        REASON="verify failed (see $ARCH.verify.log)"
      fi
    else
      REASON="boot failed (see $ARCH.boot.log)"
    fi
  else
    REASON="prepare failed (see $ARCH.prepare.log)"
  fi
  END=$(date +%s)
  echo "$ARCH $STATUS $((END - START))s $REASON" >> "$RESULT"
  ./stop_guest.sh "$ARCH" >/dev/null 2>&1 || true
  echo "[$ARCH] $STATUS ($((END - START))s)"
done

echo "===================== results ====================="
cat "$RESULT"
