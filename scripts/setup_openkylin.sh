#!/usr/bin/env bash
# One-click development/runtime environment setup for openKylin.
#
# Verified on: openKylin 3.0 (huanghe), kernel 7.0.0-2-generic, x86_64.
# Targets: eBPF collector build toolchain + Python model runtime + injection
# tools (stress-ng, fio). Idempotent: safe to re-run.
#
# Usage:
#   sudo ./scripts/setup_openkylin.sh            # full setup (toolchain + fio + python)
#   sudo ./scripts/setup_openkylin.sh --skip-python
#
# Requirements: root (or passwordless sudo). Network: openKylin apt archive,
# PyPI (or TUNA mirror), github.com (fio source), HF (checkpoint, or
# hf-mirror.com when direct access fails).
#
# See docs/env-setup-openkylin.md for the step-by-step rationale and the
# manual fallback procedures (sudo without NOPASSWD, offline checkpoint copy).
set -euo pipefail

SKIP_PYTHON=0
if [[ "${1:-}" == "--skip-python" ]]; then SKIP_PYTHON=1; fi

# ---------------------------------------------------------------------------
# 1. System packages (collector toolchain + python)
# ---------------------------------------------------------------------------
echo "[1/6] apt: collector toolchain"
# huanghe-proposed carries base packages whose versions conflict with main's
# pinned -ok3 set ("Reached two conflicting assignments"); disable it.
if grep -qE '^deb .*huanghe-proposed' /etc/apt/sources.list 2>/dev/null; then
  sed -i -E 's|^(deb .*huanghe-proposed.*)|# disabled by setup_openkylin.sh (conflicts with main): \1|' /etc/apt/sources.list
fi
# kdump-tools' kernel postinst hook builds a kdump initramfs and fails in
# VMs ("failed to determine device for /sysroot"), leaving dpkg half-broken;
# the hook is pure noise for this tool (docs 排错 4).
apt-get remove -y -qq kdump-tools 2>/dev/null || true
rm -f /etc/kernel/postinst.d/kdump-tools
dpkg --configure -a || true
apt-get update -qq
apt-get install -y \
  cmake gcc g++ make pkg-config \
  libbpf-dev libelf-dev zlib1g-dev libsqlite3-dev \
  python3-pip python3-venv \
  bpftool rsync git sqlite3

# ---------------------------------------------------------------------------
# 1b. clang: huanghe repo's clang-22 index is stale (pins libllvm22 to a
#     version no longer published -> apt cannot install it). Install clang-18
#     from Ubuntu noble via the USTC mirror instead (libllvm18 is versioned
#     separately; no conflict with the system libllvm22). BPF build only
#     needs the clang driver; llvm-strip is not used (docs 排错 5).
# ---------------------------------------------------------------------------
if ! command -v clang >/dev/null 2>&1; then
  if [ ! -f /etc/apt/sources.list.d/ubuntu-noble.list ]; then
    printf 'deb [trusted=yes] http://mirrors.ustc.edu.cn/ubuntu/ noble main universe\n' \
      > /etc/apt/sources.list.d/ubuntu-noble.list
    apt-get update -qq
  fi
  apt-get install -y -qq clang-18
  ln -sf /usr/bin/clang-18 /usr/local/bin/clang
fi
echo "clang: $(clang --version | head -1)"

# ---------------------------------------------------------------------------
# 1b. stress-ng (openKylin repo entry depends on libipsec-mb0 which is not
#     published in huanghe -> build from source; github.com reachable)
# ---------------------------------------------------------------------------
echo "[2/6] stress-ng: source build (repo dep libipsec-mb0 unavailable)"
if command -v stress-ng >/dev/null 2>&1; then
  echo "stress-ng already present: $(stress-ng --version | head -1)"
else
  apt-get install -y libaio-dev zlib1g-dev
  SNG_VER=0.17.06
  (cd /tmp && rm -rf stress-ng-"$SNG_VER" stress-ng.tgz &&
   curl -sL "https://github.com/ColinIanKing/stress-ng/archive/refs/tags/V$SNG_VER.tar.gz" -o stress-ng.tgz &&
   tar xzf stress-ng.tgz && cd stress-ng-"$SNG_VER" && make -j"$(nproc)" && make install)
  echo "stress-ng installed: $(stress-ng --version 2>&1 | head -1)"
fi

# ---------------------------------------------------------------------------
# 2. fio (absent from openKylin repos -> build from source)
# ---------------------------------------------------------------------------
echo "[3/6] fio: build from source (not packaged in openKylin)"
if command -v fio >/dev/null 2>&1; then
  echo "fio already present: $(fio --version)"
else
  apt-get install -y libaio-dev
  FIO_VER=3.36
  (cd /tmp && rm -rf fio-"$FIO_VER" fio-fio-"$FIO_VER" fio.tgz &&
   curl -sL "https://github.com/axboe/fio/archive/refs/tags/fio-$FIO_VER.tar.gz" -o fio.tgz &&
   tar xzf fio.tgz && cd fio-fio-"$FIO_VER" && ./configure --prefix=/usr/local &&
   make -j"$(nproc)" && make install)
  echo "fio installed: $(fio --version 2>&1 | head -1)"
fi

# ---------------------------------------------------------------------------
# 3. uv (pip bootstrap; astral.sh installer is the alternative)
# ---------------------------------------------------------------------------
echo "[4/6] uv via pip"
if ! command -v uv >/dev/null 2>&1; then
  pip3 install --break-system-packages uv 2>/dev/null \
    || curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"
uv --version

# ---------------------------------------------------------------------------
# 4. Python model environment (CPU core + torch extra)
# ---------------------------------------------------------------------------
if [[ $SKIP_PYTHON -eq 0 ]]; then
  echo "[5/6] model deps (uv sync, torch extra)"
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  cd "$ROOT/models"
  uv sync --extra dev --extra torch

  echo "[6/6] Time-RCD checkpoint prefetch (HF, mirror fallback)"
  if curl -s -m 6 -o /dev/null https://huggingface.co; then
    uv run python -c "from time_rcd import TimeRCDDetector; TimeRCDDetector.from_pretrained(variant='multi'); print('checkpoint cached')"
  else
    echo "huggingface.co unreachable; using hf-mirror.com"
    HF_ENDPOINT=https://hf-mirror.com uv run python -c "from time_rcd import TimeRCDDetector; TimeRCDDetector.from_pretrained(variant='multi'); print('checkpoint cached')"
  fi
else
  echo "[5/6] skipped (--skip-python)"
  echo "[6/6] skipped (--skip-python)"
fi

# ---------------------------------------------------------------------------
# Verification summary
# ---------------------------------------------------------------------------
echo "--- verification ---"
clang --version | head -1
cmake --version | head -1
bpftool version | head -1
fio --version
stress-ng --version | head -1
ls /sys/kernel/btf/vmlinux >/dev/null 2>&1 && echo "kernel BTF: present" || echo "kernel BTF: MISSING (collector cannot run)"
echo "setup done"
