#!/usr/bin/env bash
# Run the acceptance suite inside one guest over ssh:
#   1. kernel BTF present (/sys/kernel/btf/vmlinux)
#   2. collector builds (clang BPF target + libbpf)
#   3. BPF skeleton loads and BASE ticks land in the session db
#   4. mock-model DEEP trigger + evidence + diagnosis.json
#
#   ./verify_guest.sh <arch>
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ARCH="$1"
SSHPORT=$(arch_sshport "$ARCH")
SSHOPTS=(-p "$SSHPORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
         -o ConnectTimeout=10)
GUEST="root@127.0.0.1"
PW="$GUEST_ROOT_PW"

g() { sshpass -p "$PW" ssh "${SSHOPTS[@]}" "$GUEST" "$@"; }
gput() { sshpass -p "$PW" scp "${SSHOPTS[@]}" "$@" "$GUEST:/tmp/"; }

g "true" || { echo "[$ARCH] ssh not reachable" >&2; exit 1; }

echo "[$ARCH] 1/4 kernel BTF"
g 'test -f /sys/kernel/btf/vmlinux && echo BTF-PRESENT || { echo BTF-MISSING; exit 1; }'

echo "[$ARCH] 2/4 packaging repo -> guest"
TARBALL="$QEMU_DATA/repo-$ARCH.tar"
tar -C "$REPO_HOST_DIR" -cf "$TARBALL" \
  --exclude=build --exclude=node_modules --exclude=out_* --exclude=.git \
  --exclude=__pycache__ --exclude='*.sqlite3*' .
gput "$TARBALL"
g 'mkdir -p ~/repo && tar -xf /tmp/repo-*.tar -C ~/repo'

echo "[$ARCH] 3/4 toolchain + build (this is the slow step under TCG)"
g 'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq \
     clang-15 gcc g++ make cmake pkg-config libbpf-dev libelf-dev zlib1g-dev \
     libsqlite3-dev bpftool python3 websockets >/dev/null 2>&1 || true;
   cd ~/repo && (PKG=$(apt-cache policy clang-15 | grep -m1 Candidate | awk "{print \$2}"); \
   [ -n "$PKG" ] && [ "$PKG" != "(none)" ] && apt-get install -y -qq clang-15 >/dev/null 2>&1 || true);
   export PATH=/usr/local/bin:$PATH; ./scripts/build.sh 2>&1 | tail -2'

echo "[$ARCH] 4/4 BASE smoke + mock-model DEEP"
g 'cd ~/repo && OUT=/tmp/qemu_smoke && rm -rf $OUT && mkdir -p $OUT && \
   (nohup python3 -u scripts/mock_model.py --trigger-once >$OUT/mock.log 2>&1 &) && sleep 2 && \
   ETRACE_DIAG_MODEL_ANOMALY_URL=ws://127.0.0.1:9001/anomaly \
   ETRACE_DIAG_MODEL_CAUSAL_URL=ws://127.0.0.1:9002/causal \
   ETRACE_DIAG_WINDOW_PRE_ANOMALY_SECONDS=5 \
   ETRACE_DIAG_WINDOW_POST_ANOMALY_SECONDS=10 \
   ETRACE_DIAG_OUTPUT_DIR=$OUT \
   timeout 90 ./build/etrace-diag --config config/default.json --run-seconds 45 \
   >$OUT/collector.log 2>&1; echo "collector-rc=$?"'

g 'cd ~/repo && python3 - <<PYEOF
import glob, json, sqlite3, sys
sessions = sorted(glob.glob("/tmp/qemu_smoke/*/"))
if not sessions:
    print("FAIL: no session"); sys.exit(1)
db = sessions[-1] + "etrace.sqlite3"
c = sqlite3.connect(db)
host = c.execute("SELECT COUNT(*) FROM host").fetchone()[0]
deep = c.execute("SELECT COUNT(*) FROM deep_episodes").fetchone()[0]
print(f"BASE host rows: {host}; deep_episodes: {deep}")
ok = host >= 10
try:
    d = json.load(open(sessions[-1] + "diagnosis.json"))
    print("diagnosis ok:", d.get("ok"))
    ok = ok and bool(d.get("ok"))
except FileNotFoundError:
    print("diagnosis.json missing (BPF load may have failed)")
    ok = False
sys.exit(0 if ok else 1)
PYEOF'

echo "[$ARCH] acceptance PASSED"
