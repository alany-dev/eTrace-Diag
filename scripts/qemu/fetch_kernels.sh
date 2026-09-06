#!/usr/bin/env bash
# One-time fetch of the QEMU cross-arch assets: guest kernel packages for
# every arch + the EDK2/OpenSBI firmware QEMU needs for non-x86 machines.
# Optional (prepare_guest.sh pulls kernel packages itself); kept for offline
# reproducibility and BTF inspection without booting.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

MIRROR="http://archive.build.openkylin.top/openkylin"
SUITE="nile"
mkdir -p "$QEMU_DATA/pkgs"

for ARCH in $ALL_ARCHES; do
  DEBARCH=$(arch_debarch "$ARCH")
  KERNPKG=$(arch_kernpkg "$ARCH")
  IDX="$MIRROR/dists/$SUITE/main/binary-$DEBARCH/Packages.gz"
  F=$(curl -s -m 120 "$IDX" | zcat 2>/dev/null |
      awk -v pkg="Package: $KERNPKG" '$0 == pkg {inblk=1} inblk && /^Filename:/ {print $2; exit}')
  [ -n "$F" ] || { echo "[$ARCH] kernel package not found: $KERNPKG"; continue; }
  OUT="$QEMU_DATA/pkgs/$(basename "$F")"
  [ -f "$OUT" ] || { echo "[$ARCH] fetching $F"; curl -s -m 600 "$MIRROR/$F" -o "$OUT"; }
  ls -la "$OUT"
done
echo "pkgs dir: $QEMU_DATA/pkgs"
