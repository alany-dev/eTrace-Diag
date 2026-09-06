#!/usr/bin/env bash
# Boot one guest arch headless (daemonized) and wait for ssh reachability.
#
#   sudo ./boot_guest.sh <arch>
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ARCH="$1"
QBIN=$(arch_qemu "$ARCH")
MACHINE=$(arch_machine "$ARCH")
CPUARGS=$(arch_cpu "$ARCH")
CONSOLE=$(arch_console "$ARCH")
IMG=$(arch_img "$ARCH")
KERNEL=$(arch_kernel "$ARCH")
INITRD=$(arch_initrd "$ARCH")
LOG=$(arch_log "$ARCH")
PIDF=$(arch_pidfile "$ARCH")
SSHPORT=$(arch_sshport "$ARCH")

[ -f "$IMG" ] || { echo "no disk image: $IMG (run prepare_guest.sh $ARCH)" >&2; exit 1; }
[ -f "$KERNEL" ] || { echo "no kernel: $KERNEL" >&2; exit 1; }
if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  echo "[$ARCH] already running (pid $(cat "$PIDF"))"; exit 0
fi

ACCEL=$(arch_accel "$ARCH")
if [[ "$ACCEL" == *kvm* ]] && [ ! -w /dev/kvm ]; then
  ACCEL="tcg"
fi

ROOTDEV="root=/dev/vda1"
APPEND="$ROOTDEV rw console=$CONSOLE,115200 earlyprintk=serial,ttyS0,115200"

ARGS=(
  -machine "$MACHINE" $CPUARGS
  -m 2048 -smp 2
  -drive "file=$IMG,format=qcow2,if=virtio"
  -kernel "$KERNEL"
  -append "$APPEND"
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:${SSHPORT}-:22"
  -device virtio-net-pci,netdev=n0
  -serial "file:$LOG"
  -display none -daemonize -pidfile "$PIDF"
)
[ -f "$INITRD" ] && ARGS+=(-initrd "$INITRD")

"$QBIN" "${ARGS[@]}"
sleep 2
kill -0 "$(cat "$PIDF")" 2>/dev/null || { echo "qemu exited immediately; see $LOG" >&2; tail -5 "$LOG" >&2; exit 1; }

echo "[$ARCH] booting (console: $LOG, ssh: -p $SSHPORT)"
for _ in $(seq 1 120); do
  sleep 5
  if grep -qE 'login:|guest login' "$LOG" 2>/dev/null; then
    echo "[$ARCH] console ready"; break
  fi
done
ssh-keyscan -p "$SSHPORT" 127.0.0.1 >/dev/null 2>&1 && echo "[$ARCH] ssh reachable" ||
  echo "[$ARCH] WARN: ssh port not open yet (console: $LOG)"
