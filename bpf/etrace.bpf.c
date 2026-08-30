// etrace.bpf.c — single-object BPF program set for eTrace-Diag.
//
// Contract (symbols/SEC strings/map names frozen — see the design plan):
//  - Always-on programs attach once at startup; never re-armed per process.
//  - DEEP-only programs' links are created at DEEP entry / destroyed at exit
//    (the sched deep branch is instead a `deep_enabled` flag check inside the
//    always-on on_switch program).
//  - Flight recorder: single bpf_timer producer writing a per-slot-seqlock
//    ARRAY ring; cumulative counters are never reset in-kernel.
//
// NOTE on timer arming: bpf_timer_init/set_callback/start are *BPF helpers*
// and can only run in BPF context. They are driven from user space through a
// BPF_PROG_TYPE_SYSCALL program (`arm_snapshotter`) invoked via
// bpf_prog_test_run(), using `arm_cmd` as the control surface.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
// Kernels < 6.0 don't emit `struct bpf_timer` in vmlinux.h BTF; the verifier
// still requires a struct named "bpf_timer" for timer maps. Provide the
// canonical 16-byte opaque definition (matches uapi/linux/bpf.h on 6.x).
#ifndef ETD_HAVE_BPF_TIMER_UAPI
struct bpf_timer {
	__u64 :64;
	__u64 :64;
} __attribute__((aligned(8)));
#endif


#define PERF_MAX_STACK_DEPTH 127
#define HIST13_BINS 13
// bpf_num_possible_cpus (id 152) is only available >= 5.18; the host writes the
// count into the `ncpus` map at startup instead (portable across kernels).

#define HIST64_BINS 64
#define OOM_EVENTS_CAP 64

#ifndef ETD_RING_CAP
// Build-time ring capacity = power of 2 (32768) so the producer index can use
// `head & (ETD_RING_CAP-1)` — BPF has no div/mod on the default ISA, and the
// original formula ceil(90s*1000/100ms)*16*1.5 = 21600 rounds up to 2^15.
#define ETD_RING_CAP 32768
#endif

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

// ---- arch-specific syscall numbers (futex routing) ----
#ifdef __TARGET_ARCH_arm64
#define ETD_NR_FUTEX 98
#else
#define ETD_NR_FUTEX 202  // x86_64
#endif

#define FUTEX_WAIT 0
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_CMD_MASK (~(FUTEX_PRIVATE_FLAG | 256))

// REQ_OP_MASK is a preprocessor define (not in BTF): REQ_OP_BITS == 8.
#define REQ_OP_MASK 0xff

// ===========================================================================
// Shared value types
// ===========================================================================
struct switch_t { u32 vol; u32 invol; };
struct blk_io_t { u64 ops; u64 bytes; u64 lat_sum; u32 hist[HIST13_BINS]; };
struct faults_t { u32 minor; u32 major; };
// lock_st / sys_st / futex_st / runq_st share this shape.
struct lat_stat { u64 count; u64 lat_sum; u32 hist[HIST13_BINS]; };

struct snapshot_rec {
  u64 seq;                  // seqlock: odd = writing, even = committed
  u64 ts_ns;                // bpf_ktime_get_ns()
  u32 tgid, tid;
  u8  comm[16];
  // BASE (always-on) fields
  u64 on_cpu_ns;
  u32 nr_sw_vol, nr_sw_invol;
  u64 io_ops;   u64 io_bytes;   u32 io_hist[HIST13_BINS];
  u32 pf_minor; u32 pf_major;
  u64 lock_waits; u64 lock_lat_ns; u32 lock_hist[HIST13_BINS];
  // DEEP-gated fields (0 during BASE)
  u64 syscall_count; u64 syscall_lat_ns; u32 syscall_hist[HIST13_BINS];
  u64 futex_waits;   u64 futex_lat_ns;   u32 futex_hist[HIST13_BINS];
  u64 runq_wait_ns;  u32 runq_wait_count; u32 runq_hist[HIST13_BINS];
  u32 flags;                 // bit0 = deep-mode tick
};

struct task_meta_t { u32 tgid; u8 comm[16]; };

struct blk_req_t {
  u64 insert_ts;
  u64 issue_ts;
  u32 dev;
  u32 pid;
  u32 rw;
};

struct wakeup_t { u64 ts; };
struct offcpu_stash_t { u64 out_ts; u32 ksid; };
struct sys_start_t { u32 id; u64 ts; u32 user_sid; u8 futex_wait; };
struct lock_wait_t { u64 lock_addr; u64 ts; u32 flags; };

// DEEP result keys/values
struct sys_lat_key { u32 tid; u32 id; };
struct sys_lat_val { u64 count; u64 lat_sum; u32 hist[HIST64_BINS]; };
struct syscall_caller_key { u32 id; u32 user_sid; };
struct oncpu_key { u32 pid; u32 tid; u32 user_sid; u32 kernel_sid; };
struct offcpu_key { u32 tid; u32 ksid; };
struct io_file_key { u32 dev; u64 ino; char path[256]; };
struct io_file_val { u64 bytes; u32 ops; };
struct open_path_key { u32 dev; u64 ino; };
struct lock_hot_val { u64 count; u64 lat_sum; };

struct mem_events_t { u32 kswapd_active; u32 direct_reclaim; u64 nr_reclaimed; };
struct oom_event_t { u64 ts; u32 pid; };
struct ratelimit_t { u64 last_ts[4]; };
struct timer_val { struct bpf_timer t; };
struct arm_cmd_val { u64 interval_ns; u64 cancel; };
struct sample_rate_cfg { u32 offcpu_rate; u32 iofile_thresh; };

// ===========================================================================
// Maps (names frozen)
// ===========================================================================
// Targets / rank source
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, u32); } targets SEC(".maps");
// tid -> tgid/comm (populated host-side on join/pin)
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct task_meta_t); } task_meta SEC(".maps");

// Cumulative per-tid counters (PERCPU_HASH; never reset in-kernel)
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, u64); } on_cpu_ns SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct switch_t); } switches SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct blk_io_t); } block_io SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct faults_t); } faults SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct lat_stat); } lock_st SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct lat_stat); } sys_st SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct lat_stat); } futex_st SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct lat_stat); } runq_st SEC(".maps");
// per-device I/O (cumulative)
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 256);
         __type(key, u32); __type(value, struct blk_io_t); } dev_io SEC(".maps");

// Control / recorder
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u32); } deep_enabled SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } ring_head SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, struct timer_val); } timer_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u32); } snapshot_cfg SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, ETD_RING_CAP);
         __type(key, u32); __type(value, struct snapshot_rec); } recorder SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, struct snapshot_rec); } scratch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, struct mem_events_t); } mem_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, OOM_EVENTS_CAP);
         __type(key, u32); __type(value, struct oom_event_t); } oom_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u32); } oom_seq SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, struct ratelimit_t); } ratelimit SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } last_run_ts SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u32); } cur_tid SEC(".maps");
// timer arming + sampling-rate control (user-space config surface)
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, struct arm_cmd_val); } arm_cmd SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, struct sample_rate_cfg); } sample_rate_cfg SEC(".maps");
// num possible CPUs, written by the host (replaces bpf_num_possible_cpus()).
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u32); } ncpus SEC(".maps");

// Transient matching HASH
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
         __type(key, struct request *); __type(value, struct blk_req_t); } blk_req SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, u64); } wakeup_ts SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct offcpu_stash_t); } offcpu_stash SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct sys_start_t); } sys_start SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct lock_wait_t); } lock_wait SEC(".maps");

// DEEP result maps (batch-dumped at completion)
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 16384);
         __type(key, struct sys_lat_key); __type(value, struct sys_lat_val); } sys_lat SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
         __type(key, struct syscall_caller_key); __type(value, u64); } syscall_caller SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
         __type(key, struct oncpu_key); __type(value, u64); } oncpu_count SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
         __type(key, struct offcpu_key); __type(value, u64); } offcpu_time SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 16384);
         __type(key, struct io_file_key); __type(value, struct io_file_val); } io_file SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
         __type(key, struct open_path_key); __type(value, char[256]); } open_path SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u64); __type(value, struct lock_hot_val); } lock_hot SEC(".maps");

// Stacks: STACK_TRACE, value = u64 ip[127]
struct { __uint(type, BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries, 16384);
         __type(key, u32);
         __type(value, u64[PERF_MAX_STACK_DEPTH]); } stackmap SEC(".maps");

// ===========================================================================
// Helpers
// ===========================================================================
static __always_inline bool tid_is_target(u32 tid) {
  return bpf_map_lookup_elem(&targets, &tid) != NULL;
}

static __always_inline bool deep_mode(void) {
  u32 zero = 0;
  u32 *d = bpf_map_lookup_elem(&deep_enabled, &zero);
  return d && *d != 0;
}

// Hash/percpu-hash counter helpers: a hash lookup returns NULL for an absent
// key, so a bare `lookup + increment` never creates the counter. These ensure
// the key exists (zero-init, BPF_NOEXIST) then return the value pointer for the
// in-place increment. The map pointer may be a function argument — the verifier
// resolves the concrete map for key/value size checking.
static __always_inline u64 *h_u64(void *map, const void *k) {
  u64 z = 0;
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}
static __always_inline struct switch_t *h_sw(void *map, const void *k) {
  struct switch_t z = {};
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}
static __always_inline struct blk_io_t *h_blk(void *map, const void *k) {
  struct blk_io_t z = {};
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}
static __always_inline struct faults_t *h_flt(void *map, const void *k) {
  struct faults_t z = {};
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}
static __always_inline struct lat_stat *h_lat(void *map, const void *k) {
  struct lat_stat z = {};
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}
static __always_inline struct sys_lat_val *h_sys(void *map, const void *k) {
  struct sys_lat_val z = {};
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}
static __always_inline struct lock_hot_val *h_lock(void *map, const void *k) {
  struct lock_hot_val z = {};
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}
static __always_inline struct io_file_val *h_iof(void *map, const void *k) {
  struct io_file_val z = {};
  bpf_map_update_elem(map, k, &z, BPF_NOEXIST);
  return bpf_map_lookup_elem(map, k);
}

// base-4 log2 histogram: bin i = [256ns*4^i, 256ns*4^(i+1)); bin 12 = overflow.
// BPF has no native clz (and old clang backends crash lowering ctlz.i64), so
// the bin is computed with a short bounded shift loop.
static __always_inline u32 base4_bin(u64 ns) {
  if (ns < 256) return 0;
  u64 v = ns >> 8;
  u32 b = 0;
  for (int i = 0; i < 30; i++) {
    if (v < 4) break;
    v >>= 2;
    b++;
  }
  return b > 12 ? 12 : b;
}

static __always_inline void add_hist13(u32 hist[HIST13_BINS], u64 ns) {
  hist[base4_bin(ns)]++;
}

// bpf_log2l-style log2 histogram: bucket = floor(log2(value)), 64 buckets.
static __always_inline u32 log2l_bin(u64 v) {
  if (v < 2) return 0;
  u32 b = 0;
  for (int i = 0; i < 63; i++) {
    if (v < 2) break;
    v >>= 1;
    b++;
  }
  return b > 63 ? 63 : b;
}

static __always_inline void add_hist64(u32 hist[HIST64_BINS], u64 ns) {
  hist[log2l_bin(ns)]++;
}

// ===========================================================================
// Always-on: sched_switch (on-CPU attribution + deep off-CPU/runq branch)
//
// NOTE: the tp_btf context for sched/sched_switch exposes exactly the
// tracepoint's TP_PROTO args (preempt, prev, next). `prev_state` is read via
// BPF_CORE_READ(prev, __state).
// ===========================================================================
SEC("tp_btf/sched_switch")
int BPF_PROG(on_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
  u32 zero = 0;
  u64 now = bpf_ktime_get_ns();

  u32 *curp = bpf_map_lookup_elem(&cur_tid, &zero);
  u64 *lastp = bpf_map_lookup_elem(&last_run_ts, &zero);

  u32 prev_tid = curp ? *curp : 0;
  u64 start = lastp ? *lastp : 0;

  // 1. attribute on-CPU time of the outgoing (previous) tid.
  if (prev_tid && start && now > start) {
    u64 delta = now - start;
    u64 *v = h_u64(&on_cpu_ns, &prev_tid);
    if (v) *v += delta;
  }

  u32 next_pid = BPF_CORE_READ(next, pid);
  if (curp) *curp = next_pid;
  if (lastp) *lastp = now;

  u32 prev_pid = BPF_CORE_READ(prev, pid);

  // 2. switch counting + deep off-CPU branch (skip idle task).
  if (prev_pid != 0) {
    unsigned int prev_state = BPF_CORE_READ(prev, __state);
    struct switch_t *sw = h_sw(&switches, &prev_pid);
    if (prev_state == 0) {
      if (sw) sw->invol++;        // preempted while running
    } else if (prev_state & 0x7F) {
      if (sw) sw->vol++;          // blocked (sleep/stop)
    }

    // deep off-CPU: stash on real blocking sleep for target tids.
    if (deep_mode() && (prev_state != 0) && !(prev_state & 0x100) && !(prev_state & 0x80) &&
        (prev_state & 0x7F) && tid_is_target(prev_pid)) {
      struct ratelimit_t *rl = bpf_map_lookup_elem(&ratelimit, &zero);
      struct sample_rate_cfg *rc = bpf_map_lookup_elem(&sample_rate_cfg, &zero);
      u32 rate = rc ? rc->offcpu_rate : 0;
      u64 elapsed = (rl && now > rl->last_ts[0]) ? (now - rl->last_ts[0]) : 0;
      if (rl && rate && (rl->last_ts[0] == 0 || elapsed * (u64)rate >= 1000000000ULL)) {
        // tp_btf raw-tp has no pt_regs, so bpf_get_stackid cannot capture the
        // kernel stack here (it needs a kprobe/perf ctx); still record the
        // off-CPU dwell time, keyed under stack id 0.
        struct offcpu_stash_t st = {};
        st.out_ts = now;
        st.ksid = 0;
        bpf_map_update_elem(&offcpu_stash, &prev_pid, &st, BPF_ANY);
        if (rl) rl->last_ts[0] = now;
      }
    }
  }

  // 3. deep on-CPU-turned-off-CPU completion + runq latency on switch-in.
  if (deep_mode() && tid_is_target(next_pid)) {
    struct offcpu_stash_t *st = bpf_map_lookup_elem(&offcpu_stash, &next_pid);
    if (st) {
      u64 dwell = now - st->out_ts;
      struct offcpu_key k = {.tid = next_pid, .ksid = st->ksid};
      u64 *t = h_u64(&offcpu_time, &k);
      if (t) *t += dwell;
      bpf_map_delete_elem(&offcpu_stash, &next_pid);
    }
    u64 *w = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
    if (w) {
      u64 lat = now - *w;
      struct lat_stat *rq = h_lat(&runq_st, &next_pid);
      if (rq) { rq->count++; rq->lat_sum += lat; add_hist13(rq->hist, lat); }
      bpf_map_delete_elem(&wakeup_ts, &next_pid);
    }
  }

  return 0;
}

// ===========================================================================
// Always-on: sched wakeup (targets only, deep-gated)
// ===========================================================================
static __always_inline void record_wakeup(struct task_struct *p) {
  u32 pid = BPF_CORE_READ(p, pid);
  if (!deep_mode() || !tid_is_target(pid)) return;
  u64 now = bpf_ktime_get_ns();
  bpf_map_update_elem(&wakeup_ts, &pid, &now, BPF_ANY);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_wakeup, struct task_struct *p) {
  record_wakeup(p);
  return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_wakeup_new, struct task_struct *p) {
  record_wakeup(p);
  return 0;
}

// ===========================================================================
// Always-on: block I/O (issue/complete latency + per-device stats)
// ===========================================================================
SEC("tp_btf/block_rq_insert")
int BPF_PROG(on_rq_insert, struct request *rq) {
  struct blk_req_t e = {};
  e.insert_ts = bpf_ktime_get_ns();
  // gendisk.major/first_minor are stable across 5.15..6.6 and encode the
  // whole-disk devt (dev_t = major<<20 | first_minor). gendisk.devt does not
  // exist on every kernel in the supported range.
  e.dev = ((u32)BPF_CORE_READ(rq, q, disk, major) << 20) |
          (u32)BPF_CORE_READ(rq, q, disk, first_minor);
  u64 pt = bpf_get_current_pid_tgid();
  e.pid = (u32)pt;
  e.rw = BPF_CORE_READ(rq, cmd_flags) & REQ_OP_MASK;
  bpf_map_update_elem(&blk_req, &rq, &e, BPF_ANY);
  return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(on_rq_issue, struct request *rq) {
  struct blk_req_t *e = bpf_map_lookup_elem(&blk_req, &rq);
  if (!e) return 0;
  e->issue_ts = bpf_ktime_get_ns();
  return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(on_rq_complete, struct request *rq, int error, unsigned int nr_bytes) {
  (void)error;
  struct blk_req_t *e = bpf_map_lookup_elem(&blk_req, &rq);
  if (!e) return 0;
  u64 now = bpf_ktime_get_ns();
  u64 lat = e->issue_ts && now > e->issue_ts ? now - e->issue_ts : 0;
  u32 pid = e->pid;

  // per-pid block IO
  struct blk_io_t *bp = h_blk(&block_io, &pid);
  if (bp) {
    bp->ops++;
    bp->bytes += nr_bytes;
    bp->lat_sum += lat;
    add_hist13(bp->hist, lat);
  }
  // per-device block IO
  struct blk_io_t *dp = h_blk(&dev_io, &e->dev);
  if (dp) {
    dp->ops++;
    dp->bytes += nr_bytes;
    dp->lat_sum += lat;
    add_hist13(dp->hist, lat);
  }
  bpf_map_delete_elem(&blk_req, &rq);
  return 0;
}

// ===========================================================================
// Always-on: page faults (kretprobe/handle_mm_fault)
// ===========================================================================
SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(fault_ret, long ret) {
  u32 tid = (u32)bpf_get_current_pid_tgid();
  struct faults_t *f = h_flt(&faults, &tid);
  if (!f) return 0;
  if (ret & 0x4) f->major++;   // VM_FAULT_MAJOR == 0x4
  else f->minor++;
  return 0;
}

// ===========================================================================
// Always-on: vmscan (memory-pressure events)
// ===========================================================================
static __always_inline struct mem_events_t *mem_ev(void) {
  u32 zero = 0;
  return bpf_map_lookup_elem(&mem_events, &zero);
}

SEC("tp_btf/mm_vmscan_kswapd_wake")
int BPF_PROG(on_kswapd_wake, int nid, int zid, int order, gfp_t gfp_flags) {
  (void)nid; (void)zid; (void)order; (void)gfp_flags;
  struct mem_events_t *m = mem_ev();
  if (m) m->kswapd_active = 1;
  return 0;
}

SEC("tp_btf/mm_vmscan_kswapd_sleep")
int BPF_PROG(on_kswapd_sleep, int nid) {
  (void)nid;
  struct mem_events_t *m = mem_ev();
  if (m) m->kswapd_active = 0;
  return 0;
}

SEC("tp_btf/mm_vmscan_direct_reclaim_begin")
int BPF_PROG(on_direct_reclaim_begin, int order, gfp_t gfp_flags, bool may_writepage) {
  (void)order; (void)gfp_flags; (void)may_writepage;
  struct mem_events_t *m = mem_ev();
  if (m) m->direct_reclaim++;
  return 0;
}

SEC("tp_btf/mm_vmscan_direct_reclaim_end")
int BPF_PROG(on_direct_reclaim_end, unsigned long nr_reclaimed) {
  struct mem_events_t *m = mem_ev();
  if (m) m->nr_reclaimed += nr_reclaimed;
  return 0;
}

// ===========================================================================
// Always-on: OOM mark_victim (pid-only on 6.6)
// ===========================================================================
SEC("tp_btf/mark_victim")
int BPF_PROG(on_mark_victim, int pid) {
  u32 zero = 0;
  u32 *seqp = bpf_map_lookup_elem(&oom_seq, &zero);
  if (!seqp) return 0;
  u32 seq = *seqp; *seqp = seq + 1;  // best-effort ring append (rare event)
  u32 ix = seq & (OOM_EVENTS_CAP - 1);
  struct oom_event_t ev = {};
  ev.ts = bpf_ktime_get_ns();
  ev.pid = (u32)pid;
  bpf_map_update_elem(&oom_events, &ix, &ev, BPF_ANY);
  return 0;
}

// ===========================================================================
// Always-on: lock contention
//   * >= 6.0: lock:contention_begin/end tracepoints (unconditional there).
//   * < 6.0:  those tracepoints don't exist; fall back to
//             kprobe/kretprobe on __mutex_lock_slowpath.
// ===========================================================================
#ifdef ETD_HAVE_LOCK_CONTENTION_TP
SEC("tp_btf/contention_begin")
int BPF_PROG(on_contention_begin, void *lock, u32 flags) {
  u32 tid = (u32)bpf_get_current_pid_tgid();
  struct lock_wait_t w = {};
  w.lock_addr = (u64)lock;
  w.ts = bpf_ktime_get_ns();
  w.flags = flags;
  bpf_map_update_elem(&lock_wait, &tid, &w, BPF_ANY);
  return 0;
}

SEC("tp_btf/contention_end")
int BPF_PROG(on_contention_end, void *lock, int ret) {
  (void)ret;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  struct lock_wait_t *w = bpf_map_lookup_elem(&lock_wait, &tid);
  if (!w) return 0;
  u64 now = bpf_ktime_get_ns();
  u64 wait = now > w->ts ? now - w->ts : 0;

  struct lat_stat *ls = h_lat(&lock_st, &tid);
  if (ls) { ls->count++; ls->lat_sum += wait; add_hist13(ls->hist, wait); }

  u64 addr = (u64)lock;
  struct lock_hot_val *lh = h_lock(&lock_hot, &addr);
  if (lh) { lh->count++; lh->lat_sum += wait; }

  bpf_map_delete_elem(&lock_wait, &tid);
  return 0;
}
#else
SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(mutex_lock_slow, atomic_long_t *lock_count, unsigned int subclass) {
  (void)subclass;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  struct lock_wait_t w = {};
  w.lock_addr = (u64)lock_count;
  w.ts = bpf_ktime_get_ns();
  w.flags = 0;
  bpf_map_update_elem(&lock_wait, &tid, &w, BPF_ANY);
  return 0;
}

SEC("kretprobe/__mutex_lock_slowpath")
int BPF_KRETPROBE(mutex_lock_slow_ret, int ret) {
  (void)ret;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  struct lock_wait_t *w = bpf_map_lookup_elem(&lock_wait, &tid);
  if (!w) return 0;
  u64 now = bpf_ktime_get_ns();
  u64 wait = now > w->ts ? now - w->ts : 0;

  struct lat_stat *ls = h_lat(&lock_st, &tid);
  if (ls) { ls->count++; ls->lat_sum += wait; add_hist13(ls->hist, wait); }

  u64 addr = w->lock_addr;
  struct lock_hot_val *lh = h_lock(&lock_hot, &addr);
  if (lh) { lh->count++; lh->lat_sum += wait; }

  bpf_map_delete_elem(&lock_wait, &tid);
  return 0;
}
#endif

// ===========================================================================
// iter/task — per-process/thread table (BPF_TRACE_ITER)
// ===========================================================================
SEC("iter/task")
int task_iter(struct bpf_iter__task *ctx) {
  struct seq_file *seq = ctx->meta->seq;
  struct task_struct *task = ctx->task;
  if (task == (void *)0) return 0;  // terminating call

  u32 pid = BPF_CORE_READ(task, pid);
  u32 tgid = BPF_CORE_READ(task, tgid);
  char comm[16] = {};
  bpf_probe_read_kernel_str(comm, sizeof(comm), BPF_CORE_READ(task, comm));
  unsigned int state = BPF_CORE_READ(task, __state);
  u64 start_time = BPF_CORE_READ(task, start_time);
  u64 utime = BPF_CORE_READ(task, utime);
  u64 stime = BPF_CORE_READ(task, stime);
  u64 nvcsw = BPF_CORE_READ(task, nvcsw);
  u64 nivcsw = BPF_CORE_READ(task, nivcsw);
  u64 total_vm = 0;
  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  if (mm) total_vm = BPF_CORE_READ(mm, total_vm);

  BPF_SEQ_PRINTF(seq, "%u %u %s %u %llu %llu %llu %llu %llu %llu\n",
                 pid, tgid, comm, state,
                 (unsigned long long)start_time,
                 (unsigned long long)utime, (unsigned long long)stime,
                 (unsigned long long)nvcsw, (unsigned long long)nivcsw,
                 (unsigned long long)total_vm);
  return 0;
}

// ===========================================================================
// DEEP: raw syscalls enter/exit
// tp_btf exposes the tracepoint's TP_PROTO args directly:
//   raw_syscalls:sys_enter -> (struct pt_regs *regs, long id)
//   raw_syscalls:sys_exit  -> (struct pt_regs *regs, long ret)
// The syscall arguments live in the (user) pt_regs; on x86_64 the syscall
// calling convention is arg0=di, arg1=si, ..., arg5=r9.
// ===========================================================================
SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long id) {
  if (id < 0) return 0;  // compat (ia32/x32)
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;

  // raw-tp ctx has no user pt_regs stack => caller evidence degrades to 0.
  u32 user_sid = 0;

  u8 futex_wait = 0;
  if (id == ETD_NR_FUTEX) {
    unsigned long arg1;
#ifdef __TARGET_ARCH_arm64
    arg1 = BPF_CORE_READ(regs, regs[1]);
#else
    arg1 = BPF_CORE_READ(regs, si);  // x86_64: rsi = 2nd syscall arg
#endif
    u64 cmd = arg1 & FUTEX_CMD_MASK;
    if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) futex_wait = 1;
  }

  struct sys_start_t s = {};
  s.id = (u32)id;
  s.ts = bpf_ktime_get_ns();
  s.user_sid = user_sid;
  s.futex_wait = futex_wait;
  bpf_map_update_elem(&sys_start, &tid, &s, BPF_ANY);
  return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret) {
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct sys_start_t *s = bpf_map_lookup_elem(&sys_start, &tid);
  if (!s) return 0;
  u64 lat = bpf_ktime_get_ns() - s->ts;

  if (s->futex_wait) {
    struct lat_stat *f = h_lat(&futex_st, &tid);
    if (f) { f->count++; f->lat_sum += lat; add_hist13(f->hist, lat); }
  } else {
    u32 id = s->id;
    struct sys_lat_key k = {.tid = tid, .id = id};
    struct sys_lat_val *sv = h_sys(&sys_lat, &k);
    if (sv) { sv->count++; sv->lat_sum += lat; add_hist64(sv->hist, lat); }
    struct syscall_caller_key ck = {.id = id, .user_sid = s->user_sid};
    u64 *c = h_u64(&syscall_caller, &ck);
    if (c) (*c)++;
    struct lat_stat *st = h_lat(&sys_st, &tid);
    if (st) { st->count++; st->lat_sum += lat; add_hist13(st->hist, lat); }
  }

  bpf_map_delete_elem(&sys_start, &tid);
  return 0;
}

// ===========================================================================
// DEEP: on-CPU profile (perf_event)
// ===========================================================================
SEC("perf_event")
int oncpu(struct bpf_perf_event_data *ctx) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 tid = (u32)pt;                 // low 32 bits = thread id (matches targets)
  if (!tid_is_target(tid)) return 0; // target-gated, like every other DEEP hook
  u32 pid = (u32)(pt >> 32);         // aggregate key = tgid
  int user_sid = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
  int kernel_sid = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP);
  if (user_sid < 0) user_sid = 0;
  if (kernel_sid < 0) kernel_sid = 0;
  struct oncpu_key k = {.pid = pid, .tid = tid, .user_sid = (u32)user_sid, .kernel_sid = (u32)kernel_sid};
  u64 *c = h_u64(&oncpu_count, &k);
  if (c) (*c)++;
  return 0;
}

// ===========================================================================
// DEEP: hot-file I/O (kprobe/vfs_read, vfs_write) — sampled
// ===========================================================================
static __always_inline void record_file_io(struct file *f, u64 count) {
  if (!deep_mode()) return;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return;

  u32 thresh_zero = 0;
  struct sample_rate_cfg *rc = bpf_map_lookup_elem(&sample_rate_cfg, &thresh_zero);
  u32 thresh = rc ? rc->iofile_thresh : 0;
  if (thresh == 0) return;
  if (bpf_get_prandom_u32() > thresh) return;

  u32 dev = (u32)BPF_CORE_READ(f, f_inode, i_sb, s_dev);
  u64 ino = BPF_CORE_READ(f, f_inode, i_ino);

  struct io_file_key k = {};
  k.dev = dev; k.ino = ino;

  // full path if we captured it at open time, else basename fallback
  struct open_path_key opk = {};
  opk.dev = dev;
  opk.ino = ino;
  char *path = bpf_map_lookup_elem(&open_path, &opk);
  if (path && path[0]) {
    bpf_probe_read_kernel_str(k.path, sizeof(k.path), path);
  } else {
    // basename fallback (when open_path missed the open event): read
    // f_path.dentry -> d_name.name via CO-RE pointer hops.
    struct path p;
    if (bpf_core_read(&p, sizeof(p), &f->f_path) == 0 && p.dentry) {
      struct qstr q;
      if (bpf_core_read(&q, sizeof(q), &p.dentry->d_name) == 0)
        bpf_probe_read_kernel_str(k.path, sizeof(k.path), q.name);
    }
  }

  struct io_file_val *v = h_iof(&io_file, &k);
  if (v) { v->bytes += count; v->ops++; }
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(do_vfs_read, struct file *f, char *buf, size_t count, loff_t *pos) {
  (void)buf; (void)pos;
  record_file_io(f, (u64)count);
  return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(do_vfs_write, struct file *f, const char *buf, size_t count, loff_t *pos) {
  (void)buf; (void)pos;
  record_file_io(f, (u64)count);
  return 0;
}

// ===========================================================================
// DEEP: file-path capture (fentry/security_file_open — allowlisted for
// bpf_d_path on 6.6)
// ===========================================================================
SEC("fentry/security_file_open")
int BPF_PROG(file_open_path, struct file *f) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  char buf[256] = {};
  long n = bpf_d_path(&f->f_path, buf, sizeof(buf));
  if (n <= 0) return 0;

  u32 dev = (u32)BPF_CORE_READ(f, f_inode, i_sb, s_dev);
  u64 ino = BPF_CORE_READ(f, f_inode, i_ino);
  struct open_path_key k = {};
  k.dev = dev;
  k.ino = ino;
  // HASH lookup returns NULL for a new key, so write the path through
  // update_elem (create-or-overwrite) instead of lookup+memset.
  bpf_map_update_elem(&open_path, &k, buf, BPF_ANY);
  return 0;
}

// ===========================================================================
// Flight recorder: one record per target per tick. Two producer modes:
//   * >= 6.4 (ETD_HAVE_PERCPU_LOOKUP_ELEM): one bpf_timer sums each target's
//     PERCPU counters across all CPUs via bpf_map_lookup_percpu_elem, writing
//     one SUMMED record per target per tick.
//   * < 6.4: that helper does not exist; a per-CPU perf-event sampler runs on
//     every CPU and records only the CURRENT CPU's percpu slice. The host
//     merges the per-CPU records of a tick into a summed record.
// The ring head is bumped atomically (__sync_fetch_and_add, -mcpu=v3) so both
// modes share one ring.
// ===========================================================================
struct collect_ctx { u64 now; bool deep; };

static __always_inline u32 rec_ncpus(void) {
  u32 zero = 0;
  u32 *p = bpf_map_lookup_elem(&ncpus, &zero);
  return p ? *p : 64;
}

static __always_inline void rec_set_meta(struct snapshot_rec *scr, u32 tid) {
  struct task_meta_t *meta = bpf_map_lookup_elem(&task_meta, &tid);
  scr->tid = tid;
  scr->tgid = meta ? meta->tgid : 0;
  if (meta) __builtin_memcpy(scr->comm, meta->comm, 16);
}

static __always_inline long rec_commit(struct snapshot_rec *scr, u64 now, bool deep) {
  u32 zero = 0;
  u64 *headp = bpf_map_lookup_elem(&ring_head, &zero);
  if (!headp) return 0;
  u64 head = __sync_fetch_and_add(headp, 1);
  u32 ix = (u32)(head & (ETD_RING_CAP - 1));
  struct snapshot_rec *rec = bpf_map_lookup_elem(&recorder, &ix);
  if (!rec) return 0;

  scr->ts_ns = now;
  scr->flags = deep ? 1 : 0;
  scr->seq = (head << 1) | 1;  // odd = writing
  asm volatile("" ::: "memory");
  __builtin_memcpy(rec, scr, sizeof(*rec));
  asm volatile("" ::: "memory");
  rec->seq = head << 1;  // even = committed
  return 0;
}

#ifdef ETD_HAVE_PERCPU_LOOKUP_ELEM
// ---- >= 6.4: timer producer (sums a target across CPUs) ----
static long snap_collect_one(struct bpf_map *map, const void *key, void *value, void *ctx) {
  (void)map; (void)value;
  u32 tid = *(const u32 *)key;
  struct collect_ctx *c = ctx;
  u32 zero = 0;
  u32 ncpus = rec_ncpus();

  struct snapshot_rec *scr = bpf_map_lookup_elem(&scratch, &zero);
  if (!scr) return 0;
  __builtin_memset(scr, 0, sizeof(*scr));

  for (u32 cpu = 0; cpu < 1024 && cpu < ncpus; cpu++) {
    u64 *v = bpf_map_lookup_percpu_elem(&on_cpu_ns, &tid, cpu);
    if (v) scr->on_cpu_ns += *v;
    struct switch_t *sw = bpf_map_lookup_percpu_elem(&switches, &tid, cpu);
    if (sw) { scr->nr_sw_vol += sw->vol; scr->nr_sw_invol += sw->invol; }
    struct blk_io_t *bi = bpf_map_lookup_percpu_elem(&block_io, &tid, cpu);
    if (bi) {
      scr->io_ops += bi->ops; scr->io_bytes += bi->bytes;
      #pragma unroll
      for (int i = 0; i < HIST13_BINS; i++) scr->io_hist[i] += bi->hist[i];
    }
    struct faults_t *ft = bpf_map_lookup_percpu_elem(&faults, &tid, cpu);
    if (ft) { scr->pf_minor += ft->minor; scr->pf_major += ft->major; }
    struct lat_stat *ls = bpf_map_lookup_percpu_elem(&lock_st, &tid, cpu);
    if (ls) {
      scr->lock_waits += ls->count; scr->lock_lat_ns += ls->lat_sum;
      #pragma unroll
      for (int i = 0; i < HIST13_BINS; i++) scr->lock_hist[i] += ls->hist[i];
    }
    struct lat_stat *ss = bpf_map_lookup_percpu_elem(&sys_st, &tid, cpu);
    if (ss) {
      scr->syscall_count += ss->count; scr->syscall_lat_ns += ss->lat_sum;
      #pragma unroll
      for (int i = 0; i < HIST13_BINS; i++) scr->syscall_hist[i] += ss->hist[i];
    }
    struct lat_stat *fs = bpf_map_lookup_percpu_elem(&futex_st, &tid, cpu);
    if (fs) {
      scr->futex_waits += fs->count; scr->futex_lat_ns += fs->lat_sum;
      #pragma unroll
      for (int i = 0; i < HIST13_BINS; i++) scr->futex_hist[i] += fs->hist[i];
    }
    struct lat_stat *rs = bpf_map_lookup_percpu_elem(&runq_st, &tid, cpu);
    if (rs) {
      scr->runq_wait_ns += rs->lat_sum; scr->runq_wait_count += (u32)rs->count;
      #pragma unroll
      for (int i = 0; i < HIST13_BINS; i++) scr->runq_hist[i] += rs->hist[i];
    }
  }

  rec_set_meta(scr, tid);
  return rec_commit(scr, c->now, c->deep);
}

static long snap_tick(void *map, int *key, struct bpf_timer *timer) {
  (void)map; (void)key;
  u32 zero = 0;
  struct collect_ctx cctx = {.now = bpf_ktime_get_ns(), .deep = deep_mode()};
  bpf_for_each_map_elem(&targets, snap_collect_one, &cctx, 0);

  u32 *interval = bpf_map_lookup_elem(&snapshot_cfg, &zero);
  u64 interval_ns = interval ? (*interval * 1000000ULL) : 100000000ULL;
  bpf_timer_start(timer, interval_ns, 0);
  return 0;
}

SEC("syscall")
int arm_snapshotter(void *ctx) {
  (void)ctx;
  u32 zero = 0;
  struct timer_val *tv = bpf_map_lookup_elem(&timer_map, &zero);
  struct arm_cmd_val *cmd = bpf_map_lookup_elem(&arm_cmd, &zero);
  if (!tv || !cmd) return 0;
  struct bpf_timer *t = &tv->t;
  if (cmd->cancel) {
    bpf_timer_cancel(t);
    return 0;
  }
  bpf_timer_init(t, &timer_map, CLOCK_MONOTONIC);
  bpf_timer_set_callback(t, snap_tick);
  bpf_timer_start(t, cmd->interval_ns, 0);
  return 0;
}
#else
// ---- < 6.4: per-CPU perf-event sampler (current-CPU percpu slice) ----
static void collect_tid_current_cpu(u32 tid, struct snapshot_rec *scr) {
  u64 *v = h_u64(&on_cpu_ns, &tid);
  if (v) scr->on_cpu_ns = *v;
  struct switch_t *sw = h_sw(&switches, &tid);
  if (sw) { scr->nr_sw_vol = sw->vol; scr->nr_sw_invol = sw->invol; }
  struct blk_io_t *bi = h_blk(&block_io, &tid);
  if (bi) {
    scr->io_ops = bi->ops; scr->io_bytes = bi->bytes;
    #pragma unroll
    for (int i = 0; i < HIST13_BINS; i++) scr->io_hist[i] = bi->hist[i];
  }
  struct faults_t *ft = h_flt(&faults, &tid);
  if (ft) { scr->pf_minor = ft->minor; scr->pf_major = ft->major; }
  struct lat_stat *ls = h_lat(&lock_st, &tid);
  if (ls) {
    scr->lock_waits = ls->count; scr->lock_lat_ns = ls->lat_sum;
    #pragma unroll
    for (int i = 0; i < HIST13_BINS; i++) scr->lock_hist[i] = ls->hist[i];
  }
  struct lat_stat *ss = h_lat(&sys_st, &tid);
  if (ss) {
    scr->syscall_count = ss->count; scr->syscall_lat_ns = ss->lat_sum;
    #pragma unroll
    for (int i = 0; i < HIST13_BINS; i++) scr->syscall_hist[i] = ss->hist[i];
  }
  struct lat_stat *fs = h_lat(&futex_st, &tid);
  if (fs) {
    scr->futex_waits = fs->count; scr->futex_lat_ns = fs->lat_sum;
    #pragma unroll
    for (int i = 0; i < HIST13_BINS; i++) scr->futex_hist[i] = fs->hist[i];
  }
  struct lat_stat *rs = h_lat(&runq_st, &tid);
  if (rs) {
    scr->runq_wait_ns = rs->lat_sum; scr->runq_wait_count = (u32)rs->count;
    #pragma unroll
    for (int i = 0; i < HIST13_BINS; i++) scr->runq_hist[i] = rs->hist[i];
  }
}

static long snap_collect_one_cpu(struct bpf_map *map, const void *key, void *value, void *ctx) {
  (void)map; (void)value;
  u32 tid = *(const u32 *)key;
  struct collect_ctx *c = ctx;
  u32 zero = 0;
  struct snapshot_rec *scr = bpf_map_lookup_elem(&scratch, &zero);
  if (!scr) return 0;
  __builtin_memset(scr, 0, sizeof(*scr));
  collect_tid_current_cpu(tid, scr);
  rec_set_meta(scr, tid);
  return rec_commit(scr, c->now, c->deep);
}

SEC("perf_event")
int snapshotter(struct bpf_perf_event_data *ctx) {
  (void)ctx;
  struct collect_ctx c = {.now = bpf_ktime_get_ns(), .deep = deep_mode()};
  bpf_for_each_map_elem(&targets, snap_collect_one_cpu, &c, 0);
  return 0;
}
#endif

char LICENSE[] SEC("license") = "GPL";