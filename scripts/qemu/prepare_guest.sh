#!/usr/bin/env bash
# Prepare a minimal openKylin rootfs + boot kernel for one guest arch.
#
#   sudo ./prepare_guest.sh <x86_64|arm64|loong64|riscv64>
#
# Steps: debootstrap the "nile" suite (foreign stage + qemu-user second stage
# for non-amd64), install the arch kernel package, enable serial console +
# root ssh, and extract vmlinuz/initrd for direct -kernel boot.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ $# -ge 1 ] || { echo "usage: $0 <arch>" >&2; exit 2; }
ARCH="$1"
DEBARCH=$(arch_debarch "$ARCH")
KERNPKG=$(arch_kernpkg "$ARCH")
ROOTFS=$(arch_rootfs "$ARCH")
[ "$(id -u)" = 0 ] || { echo "run as root (debootstrap + mounts)"; exit 1; }

ensure_host_deps
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS" "$(dirname "$(arch_kernel "$ARCH")")"

echo "[$ARCH] debootstrap $SUITE/$DEBARCH (stage 1)"
debootstrap --arch="$DEBARCH" --variant=minbase --foreign \
  "$SUITE" "$ROOTFS" "$MIRROR" >/dev/null 2>&1

if [ "$DEBARCH" != amd64 ]; then
  echo "[$ARCH] debootstrap stage 2 under qemu-user"
  cp /usr/bin/qemu-"$DEBARCH"-static "$ROOTFS/usr/bin/" 2>/dev/null || true
  mount --bind /proc "$ROOTFS/proc"; mount --bind /sys "$ROOTFS/sys"
  mount --bind /dev "$ROOTFS/dev"
  chroot "$ROOTFS" /debootstrap/debootstrap --second-stage >/dev/null 2>&1
  umount "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" 2>/dev/null || true
else
  mount --bind /proc "$ROOTFS/proc"; mount --bind /sys "$ROOTFS/sys"
  chroot "$ROOTFS" /debootstrap/debootstrap --second-stage >/dev/null 2>&1
  umount "$ROOTFS/proc" "$ROOTFS/sys" 2>/dev/null || true
fi

# apt sources + base config inside the guest
mkdir -p "$ROOTFS/etc/apt/sources.list.d"
cat > "$ROOTFS/etc/apt/sources.list" <<EOF
deb $MIRROR $SUITE main
EOF
cat > "$ROOTFS/etc/apt/apt.conf.d/99recommends" <<'EOF'
APT::Install-Recommends "false";
EOF
echo "root:$GUEST_ROOT_PW" | chroot "$ROOTFS" chpasswd
echo "$ARCH-guest" > "$ROOTFS/etc/hostname"
cat > "$ROOTFS/etc/hosts" <<EOF
127.0.0.1 localhost $ARCH-guest
EOF
cat > "$ROOTFS/etc/ssh/sshd_config.d/99-root.conf" <<'EOF'
PermitRootLogin yes
EOF

# kernel package: fetch from the archive index and unpack into the rootfs
# (dpkg -x avoids running initramfs hooks under emulation for every boot).
echo "[$ARCH] installing kernel package $KERNPKG"
IDX="$MIRROR/dists/$SUITE/main/binary-$DEBARCH/Packages.gz"
mkdir -p /tmp/qemu-kern-"$ARCH"
curl -s -m 120 "$IDX" -o /tmp/qemu-kern-"$ARCH"/Packages.gz
KF=$(zcat /tmp/qemu-kern-"$ARCH"/Packages.gz |
     awk -v pkg="Package: $KERNPKG" '$0 == pkg {inblk=1} inblk && /^Filename:/ {print $2; exit}')
[ -n "$KF" ] || { echo "kernel package $KERNPKG not found for $DEBARCH" >&2; exit 1; }
curl -s -m 600 "$MIRROR/$KF" -o /tmp/qemu-kern-"$ARCH"/kernel.deb
dpkg-deb -x /tmp/qemu-kern-"$ARCH"/kernel.deb "$ROOTFS"

# extract vmlinuz + initrd for direct -kernel boot
KVER=$(ls "$ROOTFS/boot" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -1)
cp "$ROOTFS/boot/vmlinuz-$KVER" "$(arch_kernel "$ARCH")"
if [ -f "$ROOTFS/boot/initrd.img-$KVER" ]; then
  cp "$ROOTFS/boot/initrd.img-$KVER" "$(arch_initrd "$ARCH")"
fi

# enable serial console getty
cat > "$ROOTFS/etc/systemd/system/serial-getty@.service.d/override.conf" <<EOF
[Service]
ExecStartPre=-/sbin/agetty --help
EOF
mkdir -p "$ROOTFS/etc/systemd/system/serial-getty@$(arch_console "$ARCH").service.d"
cat > "$ROOTFS/etc/systemd/system/serial-getty@$(arch_console "$ARCH").service.d/autologin.conf" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -u root' --autologin root --noclear $(arch_console "$ARCH") 115200,38400,9600 linux
EOF

# make the disk image
make_disk "$ARCH" 4096
echo "[$ARCH] prepared: $(arch_img "$ARCH")  kernel=$(arch_kernel "$ARCH")"
