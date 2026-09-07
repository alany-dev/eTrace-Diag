#!/usr/bin/env bash
# Prepare a minimal openKylin guest rootfs + boot kernel + initramfs.
#
#   sudo ./prepare_guest.sh <x86_64|arm64|loong64|riscv64>
#
# x86_64: native chroot. Other arches: debootstrap --foreign + qemu-user
# second stage, then apt inside the chroot runs under qemu-user-static.
# Kernel package installed properly (postinst builds the initramfs), which
# also resolves every shared-library dependency of systemd/ssh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[ $# -ge 1 ] || { echo "usage: $0 <arch>" >&2; exit 2; }
ARCH="$1"
DEBARCH=$(arch_debarch "$ARCH")
KERNPKG=$(arch_kernpkg "$ARCH")
ROOTFS=$(arch_rootfs "$ARCH")
LOG="$QEMU_DATA/$ARCH.prepare.log"
mkdir -p "$QEMU_DATA" "$(dirname "$ROOTFS")"
exec > >(tee -a "$LOG") 2>&1

ensure_host_deps
# Never blind-wipe: if proc/sys/dev are still bind-mounted (crashed prior run),
# rm -rf follows into the HOST /dev and destroys device nodes (observed:
# host /dev/null became a regular file). Detach first, then wipe.
if mountpoint -q "$ROOTFS/dev" || mountpoint -q "$ROOTFS/proc" || mountpoint -q "$ROOTFS/sys"; then
  umount -l "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" 2>/dev/null || true
fi
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"

echo "[$ARCH] debootstrap $SUITE/$DEBARCH (stage 1)"
debootstrap --no-check-gpg --merged-usr --arch="$DEBARCH" --variant=minbase --foreign \
  "$SUITE" "$ROOTFS" "$MIRROR"

if [ "$DEBARCH" != amd64 ]; then
  echo "[$ARCH] debootstrap stage 2 under qemu-user"
  cp /usr/bin/qemu-"$DEBARCH"-static "$ROOTFS/usr/bin/" || true
fi
mount --bind /proc "$ROOTFS/proc" 2>/dev/null || true
mount --bind /sys  "$ROOTFS/sys"  2>/dev/null || true
mount --bind /dev  "$ROOTFS/dev"  2>/dev/null || true
chroot "$ROOTFS" /debootstrap/debootstrap --second-stage
umount "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" 2>/dev/null || true

# apt sources + base config inside the guest
mkdir -p "$ROOTFS/etc/apt/sources.list.d" "$ROOTFS/etc/ssh/sshd_config.d"
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

# DHCP on the first NIC: without a .network match systemd-networkd leaves
# ens3 unaddressed and the user-mode hostfwd (ssh) never connects.
mkdir -p "$ROOTFS/etc/systemd/network"
cat > "$ROOTFS/etc/systemd/network/80-dhcp.network" <<'EOF'
[Match]
Name=en* eth*

[Network]
DHCP=yes
EOF

# minbase systemd ships networkd disabled: enable it or ens3 stays unaddressed.
mkdir -p "$ROOTFS/etc/systemd/system/multi-user.target.wants"
ln -sf /lib/systemd/system/systemd-networkd.service \
  "$ROOTFS/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
ln -sf /lib/systemd/system/systemd-networkd.socket \
  "$ROOTFS/etc/systemd/system/multi-user.target.wants/systemd-networkd.socket"
ln -sf /lib/systemd/system/systemd-resolved.service \
  "$ROOTFS/etc/systemd/system/multi-user.target.wants/systemd-resolved.service" 2>/dev/null || true

# -------- in-chroot package install (native on amd64, qemu-user otherwise)
mount --bind /proc "$ROOTFS/proc" 2>/dev/null || true
mount --bind /sys  "$ROOTFS/sys"  2>/dev/null || true
mount --bind /dev  "$ROOTFS/dev"  2>/dev/null || true

echo "[$ARCH] apt update + base packages"
chroot "$ROOTFS" /bin/sh -c "
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv openssh-server iproute2 \
    kmod e2fsprogs ca-certificates 2>&1 | tail -2
"

echo "[$ARCH] installing kernel package $KERNPKG (initramfs generated)"
chroot "$ROOTFS" /bin/sh -c "
  apt-get install -y -qq --no-install-recommends $KERNPKG initramfs-tools 2>&1 | tail -2
"

# initramfs must exist for -kernel/-initrd direct boot; the kernel postinst
# alone is unreliable inside a debootstrap chroot (no udev events).
KVER=$(ls "$ROOTFS/boot" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -1)
chroot "$ROOTFS" update-initramfs -k "$KVER" -c 2>&1 | tail -1 || true
umount "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev" 2>/dev/null || true

# serial console getty + autologin
CONSOLE=$(arch_console "$ARCH")
mkdir -p "$ROOTFS/etc/systemd/system/serial-getty@$CONSOLE.service.d"
cat > "$ROOTFS/etc/systemd/system/serial-getty@$CONSOLE.service.d/autologin.conf" <<EOF
[Service]
ExecStart=-/sbin/agetty --autologin root --noclear $CONSOLE 115200,38400,9600 linux
EOF

# extract kernel + initramfs for direct -kernel boot
mkdir -p "$(dirname "$(arch_kernel "$ARCH")")"
# openKylin kernel postinst may name the initrd with or without the version
KVER=$(ls "$ROOTFS/boot" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -1)
cp "$ROOTFS/boot/vmlinuz-$KVER" "$(arch_kernel "$ARCH")"
if [ -f "$ROOTFS/boot/initrd.img-$KVER" ]; then
  cp "$ROOTFS/boot/initrd.img-$KVER" "$(arch_initrd "$ARCH")"
elif [ -f "$ROOTFS/boot/initrd.img" ]; then
  cp "$ROOTFS/boot/initrd.img" "$(arch_initrd "$ARCH")"
else
  echo "[$ARCH] WARN: no initrd.img-$KVER / initrd.img in rootfs/boot" >&2
fi

make_disk "$ARCH" 6144
echo "[$ARCH] prepared: $(arch_img "$ARCH")  kernel=$(arch_kernel "$ARCH")  initrd=$(arch_initrd "$ARCH")"
