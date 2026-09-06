#!/usr/bin/env bash
# Shared configuration for the QEMU cross-arch openKylin guests.
#
# Each arch entry drives prepare_guest.sh / boot_guest.sh / verify_guest.sh.
# All data lives under $QEMU_DATA (default: <repo>/build/qemu, gitignored).
#
# Guest suite: openKylin "nile" (2.2, kernel 6.6.0-15 on amd64/arm64/loong64).
# riscv64: nile only ships a 5.15.65-rt kernel (documented deviation).
#
# Repo layout (openKylin archive):
#   http://archive.build.openkylin.top/openkylin/dists/nile/main/binary-<debarch>/
set -euo pipefail

QEMU_ROOT="${QEMU_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
QEMU_DATA="${QEMU_DATA:-$QEMU_ROOT/build/qemu}"
REPO_HOST_DIR="${REPO_HOST_DIR:-$QEMU_ROOT}"
MIRROR="${MIRROR:-http://archive.build.openkylin.top/openkylin}"
SUITE="${SUITE:-nile}"
GUEST_ROOT_PW="${GUEST_ROOT_PW:-root}"
SSH_BASE_PORT="${SSH_BASE_PORT:-2222}"

# debarch | kernelpkg (empty = linux-image-virtual meta) | qemu bin | machine | cpu args | console | ssh port offset | accel
arch_cfg() {
  case "$1" in
    x86_64)
      echo "amd64|linux-image-unsigned-6.6.0-15-generic|qemu-system-x86_64|pc|accel=kvm -cpu host|ttyS0|0|kvm" ;;
    arm64)
      echo "arm64|linux-image-unsigned-6.6.0-15-generic|qemu-system-aarch64|virt|-cpu max|ttyAMA0|1|tcg" ;;
    loong64)
      echo "loong64|linux-image-6.6.0-15-generic|qemu-system-loongarch64|virt|-cpu max|ttyS0|2|tcg" ;;
    riscv64)
      echo "riscv64|linux-image-5.15.65-rt56+|qemu-system-riscv64|virt|-cpu max|ttyS0|3|tcg" ;;
    *) echo "unknown arch: $1" >&2; return 1 ;;
  esac
}

fields() { echo "$1" | tr '|' '\n'; }
field() { echo "$1" | tr '|' '\n' | sed -n "$2p"; }

arch_debarch()   { field "$(arch_cfg "$1")" 1; }
arch_kernpkg()   { field "$(arch_cfg "$1")" 2; }
arch_qemu()      { field "$(arch_cfg "$1")" 3; }
arch_machine()   { field "$(arch_cfg "$1")" 4; }
arch_cpu()       { field "$(arch_cfg "$1")" 5; }
arch_console()   { field "$(arch_cfg "$1")" 6; }
arch_sshport()   { echo "$((SSH_BASE_PORT + $(field "$(arch_cfg "$1")" 7)))"; }
arch_accel()     { field "$(arch_cfg "$1")" 8; }

arch_dir()    { echo "$QEMU_DATA/$1"; }
arch_rootfs() { echo "$QEMU_DATA/$1/rootfs"; }
arch_img()    { echo "$QEMU_DATA/$1/disk.qcow2"; }
arch_kernel() { echo "$QEMU_DATA/$1/boot/vmlinuz"; }
arch_initrd() { echo "$QEMU_DATA/$1/boot/initrd.img"; }
arch_log()    { echo "$QEMU_DATA/$1/console.log"; }
arch_pidfile(){ echo "$QEMU_DATA/$1/qemu.pid"; }

ALL_ARCHES="${ALL_ARCHES:-x86_64 arm64 loong64 riscv64}"

ensure_host_deps() {
  local need=()
  for t in debootstrap qemu-img; do
    command -v "$t" >/dev/null 2>&1 || need+=("$t")
  done
  if [ ${#need[@]} -gt 0 ]; then
    apt-get install -y -qq debootstrap qemu-utils "${need[@]/qemu-img/}"
  fi
}

# Build an ext4 disk image from a populated rootfs directory.
make_disk() { # $1 arch  $2 size_mb
  local dir="$1" size="${2:-4096}"
  local img disk_mnt
  img=$(arch_img "$dir")
  mkdir -p "$(dirname "$img")"
  rm -f "$img"
  qemu-img create -f qcow2 "$img" "${size}M" >/dev/null
  disk_mnt=$(mktemp -d)
  mkfs.ext4 -F -q "$img" 2>/dev/null || mkfs.ext4 -F "$img"
  mount "$img" "$disk_mnt"
  cp -a "$(arch_rootfs "$dir")/." "$disk_mnt/"
  umount "$disk_mnt"
  rmdir "$disk_mnt"
}
