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
#ifndef NR_MM_COUNTERS
#define NR_MM_COUNTERS 4
#endif

// AF_* and TCP_* are preprocessor defines/enums absent from vmlinux.h BTF.
#define AF_INET 2
#define AF_INET6 10
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_FIN_WAIT1 4
#define TCP_FIN_WAIT2 5
#define TCP_TIME_WAIT 6
#define TCP_CLOSE 7
#define TCP_CLOSE_WAIT 8
#define TCP_LAST_ACK 9
#define TCP_LISTEN 10
#define TCP_CLOSING 11

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
struct offcpu_stash_t { u64 out_ts; u32 ksid; u32 stack_available; };
struct sys_start_t { u32 id; u64 ts; u8 futex_wait; };
struct lock_wait_t { u64 lock_addr; u64 ts; u32 flags; };
struct io_start_t { u32 dev; u64 ino; char path[256]; u64 ts; };

// DEEP network value types
struct sock_owner_t {
  u64 tgid;
  u32 tid;
  u64 netns_ino;
  u32 family;
  u32 local_addr[4];    // v4 in [0]; v6 across all four
  u32 remote_addr[4];
  u32 local_port;       // network byte order
  u32 remote_port;
  u64 start_ts;
  u64 established_ts;
  u64 tx_bytes;
  u64 rx_bytes;
  u64 retrans;
  u32 rst_reason;
  u64 rtt_count;
  u64 rtt_sum_us;       // srtt samples summed (us)
};
struct connect_start_t { u64 cookie; u64 ts; };
struct net_drop_key { u64 netns_ino; u32 ifindex; u32 reason_id; };
struct net_softirq_key { u32 cpu_idx; u32 vector; };
struct flow_key { u64 cookie; };

// DEEP result keys/values
struct sys_lat_key { u32 tid; u32 id; };
struct sys_lat_val { u64 count; u64 lat_sum; u64 error_count; u32 hist[HIST64_BINS]; };
struct oncpu_key { u32 pid; u32 tid; u32 user_sid; u32 kernel_sid; };
struct offcpu_key { u32 tid; u32 ksid; };
struct io_file_key { u32 dev; u64 ino; char path[256]; };
struct io_file_val { u64 bytes; u32 ops; u64 errors; u64 lat_sum; u32 hist[HIST13_BINS]; };
struct lock_hot_val { u64 count; u64 lat_sum; };

struct mem_events_t { u32 kswapd_active; u32 direct_reclaim; u64 nr_reclaimed; };
struct oom_event_t { u64 ts; u32 pid; };
struct ratelimit_t { u64 last_ts[4]; };
struct timer_val { struct bpf_timer t; };
struct arm_cmd_val { u64 interval_ns; u64 cancel; };
struct sample_rate_cfg { u32 offcpu_rate; u32 iofile_thresh; u32 net_rate; };

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
         __type(key, struct oncpu_key); __type(value, u64); } oncpu_count SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
         __type(key, struct offcpu_key); __type(value, u64); } offcpu_time SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 16384);
         __type(key, struct io_file_key); __type(value, struct io_file_val); } io_file SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct io_start_t); } io_start SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u64); __type(value, struct lock_hot_val); } lock_hot SEC(".maps");
// Stackless off-CPU dwell aggregated per tid (dumped as deep_offcpu).
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct lat_stat); } offcpu_stat SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, u64); } offcpu_last_ts SEC(".maps");
// Set by the host when offcpu_schedule (kprobe/__schedule) is unavailable:
// on_switch then records stackless off-CPU dwell (stack_available=0).
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u32); } offcpu_fallback SEC(".maps");

// DEEP network maps (all max_entries per the frozen contract)
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 16384);
         __type(key, u64); __type(value, struct sock_owner_t); } sock_owner SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 16384);
         __type(key, u64); __type(value, struct sock_owner_t); } net_flow SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, u32); __type(value, struct connect_start_t); } connect_start SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 4096);
         __type(key, struct net_drop_key); __type(value, u64); } net_drop SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_HASH); __uint(max_entries, 1024);
         __type(key, struct net_softirq_key); __type(value, struct lat_stat); } net_softirq SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
         __type(key, u64); __type(value, u64); } rtt_last SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __type(key, u32); __type(value, u64); } softirq_enter_ts SEC(".maps");

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

  // 1. attribute on-CPU time of the outgoing (previous) tid — targets only.
  if (prev_tid && start && now > start && tid_is_target(prev_tid)) {
    u64 delta = now - start;
    u64 *v = h_u64(&on_cpu_ns, &prev_tid);
    if (v) *v += delta;
  }

  u32 next_pid = BPF_CORE_READ(next, pid);
  if (curp) *curp = next_pid;
  if (lastp) *lastp = now;

  u32 prev_pid = BPF_CORE_READ(prev, pid);

  // 2. switch counting — targets only (idle task skipped).
  if (prev_pid != 0 && tid_is_target(prev_pid)) {
    unsigned int prev_state = BPF_CORE_READ(prev, __state);
    struct switch_t *sw = h_sw(&switches, &prev_pid);
    if (prev_state == 0) {
      if (sw) sw->invol++;        // preempted while running
    } else if (prev_state & 0x7F) {
      if (sw) sw->vol++;          // blocked (sleep/stop)
    }
  }

  // 2b. stackless off-CPU fallback stash (kprobe/__schedule unavailable):
  //     dwell-only samples land in offcpu_stat -> deep_offcpu.
  if (deep_mode() && prev_pid != 0 && tid_is_target(prev_pid)) {
    unsigned int pv_state = BPF_CORE_READ(prev, __state);
    if ((pv_state != 0) && !(pv_state & 0x100) && !(pv_state & 0x80) && (pv_state & 0x7F)) {
      u32 *fb = bpf_map_lookup_elem(&offcpu_fallback, &zero);
      if (fb && *fb) {
        u64 *last = bpf_map_lookup_elem(&offcpu_last_ts, &prev_pid);
        struct sample_rate_cfg *rc = bpf_map_lookup_elem(&sample_rate_cfg, &zero);
        u32 rate = rc ? rc->offcpu_rate : 0;
        u64 elapsed = (last && now > *last) ? (now - *last) : 0;
        if (last && rate && (*last == 0 || elapsed * (u64)rate >= 1000000000ULL)) {
          struct offcpu_stash_t st = {};
          st.out_ts = now;
          st.ksid = 0;
          st.stack_available = 0;
          bpf_map_update_elem(&offcpu_stash, &prev_pid, &st, BPF_ANY);
          *last = now;
        }
      }
    }
  }

  // 3. off-CPU completion + runq latency on switch-in.
  if (deep_mode() && tid_is_target(next_pid)) {
    struct offcpu_stash_t *st = bpf_map_lookup_elem(&offcpu_stash, &next_pid);
    if (st) {
      u64 dwell = now - st->out_ts;
      if (st->stack_available) {
        // Stacked sample: fold under its kernel stack id (ksid==0 still
        // recorded — deep_folded handles it; caller marks stack_available).
        struct offcpu_key k = {.tid = next_pid, .ksid = st->ksid};
        u64 *t = h_u64(&offcpu_time, &k);
        if (t) *t += dwell;
      } else {
        // Stackless sample: per-tid aggregation for deep_offcpu.
        struct lat_stat *o = h_lat(&offcpu_stat, &next_pid);
        if (o) { o->count++; o->lat_sum += dwell; add_hist13(o->hist, dwell); }
      }
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
  // BPF_NOEXIST keeps the EARLIEST uncompleted wakeup; on_switch deletes it.
  bpf_map_update_elem(&wakeup_ts, &pid, &now, BPF_NOEXIST);
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
// DEEP optional: kprobe/__schedule off-CPU stack capture. bpf_get_stackid is
// legal in kprobe context (unlike tp_btf). Rate-limited per tid; on_switch
// completes the dwell pairing on switch-in.
// ===========================================================================
SEC("kprobe/__schedule")
int BPF_KPROBE(offcpu_schedule) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;

  u64 now = bpf_ktime_get_ns();
  u64 *last = bpf_map_lookup_elem(&offcpu_last_ts, &tid);
  u32 zero = 0;
  struct sample_rate_cfg *rc = bpf_map_lookup_elem(&sample_rate_cfg, &zero);
  u32 rate = rc ? rc->offcpu_rate : 0;
  u64 elapsed = (last && now > *last) ? (now - *last) : 0;
  if (!last || !rate || (*last == 0 || elapsed * (u64)rate >= 1000000000ULL)) {
    int ksid = bpf_get_stackid(ctx, &stackmap, BPF_F_FAST_STACK_CMP);
    struct offcpu_stash_t st = {};
    st.out_ts = now;
    st.ksid = ksid >= 0 ? (u32)ksid : 0;
    st.stack_available = ksid >= 0 ? 1 : 0;
    bpf_map_update_elem(&offcpu_stash, &tid, &st, BPF_ANY);
    if (last) *last = now;
    else {
      u64 z = now;
      bpf_map_update_elem(&offcpu_last_ts, &tid, &z, BPF_ANY);
    }
  }
  return 0;
}

// DEEP optional: cleanup for killed/exited tasks — stale wait timestamps would
// produce bogus dwell/latency on tid reuse.
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_process_exit, struct task_struct *p) {
  u32 tid = BPF_CORE_READ(p, pid);
  bpf_map_delete_elem(&wakeup_ts, &tid);
  bpf_map_delete_elem(&offcpu_stash, &tid);
  bpf_map_delete_elem(&offcpu_last_ts, &tid);
  bpf_map_delete_elem(&sys_start, &tid);
  bpf_map_delete_elem(&io_start, &tid);
  bpf_map_delete_elem(&connect_start, &tid);
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
  if (!tid_is_target(tid)) return 0;
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
  u64 min_flt = 0, maj_flt = 0;
  if (bpf_core_field_exists(task->min_flt) && bpf_core_field_exists(task->maj_flt)) {
    min_flt = BPF_CORE_READ(task, min_flt);
    maj_flt = BPF_CORE_READ(task, maj_flt);
  }
  // ioac: rchar/wchar/syscr/syscw/read_bytes/write_bytes (cumulative)
  u64 rchar = 0, wchar = 0, syscr = 0, syscw = 0, rd_bytes = 0, wr_bytes = 0;
  if (bpf_core_field_exists(task->ioac)) {
    rchar = BPF_CORE_READ(task, ioac.rchar);
    wchar = BPF_CORE_READ(task, ioac.wchar);
    syscr = BPF_CORE_READ(task, ioac.syscr);
    syscw = BPF_CORE_READ(task, ioac.syscw);
    rd_bytes = BPF_CORE_READ(task, ioac.read_bytes);
    wr_bytes = BPF_CORE_READ(task, ioac.write_bytes);
  }
  // schedstat: se.sum_exec_runtime + sched_info.run_delay
  u64 sum_exec = 0, run_delay = 0;
  if (bpf_core_field_exists(task->se)) sum_exec = BPF_CORE_READ(task, se.sum_exec_runtime);
  if (bpf_core_field_exists(task->sched_info)) run_delay = BPF_CORE_READ(task, sched_info.run_delay);

  u64 total_vm = 0, rss_anon = 0, rss_file = 0, rss_shmem = 0, swap_ents = 0;
  struct mm_struct *mm = BPF_CORE_READ(task, mm);
  if (mm) {
    total_vm = BPF_CORE_READ(mm, total_vm);
    if (bpf_core_field_exists(mm->rss_stat)) {
      // rss_stat.count[] is atomic64_t on 5.15: copy the raw long value.
      bpf_core_read(&rss_file, 8, &mm->rss_stat.count[MM_FILEPAGES]);
      bpf_core_read(&rss_anon, 8, &mm->rss_stat.count[MM_ANONPAGES]);
      bpf_core_read(&rss_shmem, 8, &mm->rss_stat.count[MM_SHMEMPAGES]);
      // MM_SWAPENTS exists on every supported kernel (>=5.9); index 2 in
      // both 5.15 and 6.6 BTF.
      if (NR_MM_COUNTERS > 2)
        bpf_core_read(&swap_ents, 8, &mm->rss_stat.count[2]);
    }
  }

  // bpf_seq_printf caps at 12 varargs -> three prefixed lines per task.
  BPF_SEQ_PRINTF(seq, "A %u %u %s %u %llu %llu %llu %llu %llu %llu %llu\n",
                 pid, tgid, comm, state,
                 (unsigned long long)start_time,
                 (unsigned long long)utime, (unsigned long long)stime,
                 (unsigned long long)nvcsw, (unsigned long long)nivcsw,
                 (unsigned long long)min_flt, (unsigned long long)maj_flt);
  BPF_SEQ_PRINTF(seq, "B %u %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
                 pid,
                 (unsigned long long)total_vm,
                 (unsigned long long)rchar, (unsigned long long)wchar,
                 (unsigned long long)syscr, (unsigned long long)syscw,
                 (unsigned long long)rd_bytes, (unsigned long long)wr_bytes,
                 (unsigned long long)sum_exec, (unsigned long long)run_delay);
  BPF_SEQ_PRINTF(seq, "C %u %llu %llu %llu %llu\n",
                 pid,
                 (unsigned long long)rss_anon, (unsigned long long)rss_file,
                 (unsigned long long)rss_shmem, (unsigned long long)swap_ents);
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

// ===========================================================================
// DEEP: syscall latency — PRIMARY path fentry/fexit on do_syscall_64.
// One entry + one exit point covers every syscall on x86_64; per-call cost is
// an order of magnitude below the raw_syscalls tracepoint pair. Still
// machine-fire + target early-return: any kernel tracing hook fires for the
// whole machine, so the gate is a single pid check + hash lookup.
// ===========================================================================
static __always_inline void syslat_account(u32 tid, u32 id, u8 futex_wait, u64 lat, long ret) {
  if (futex_wait) {
    struct lat_stat *f = h_lat(&futex_st, &tid);
    if (f) { f->count++; f->lat_sum += lat; add_hist13(f->hist, lat); }
  } else {
    struct sys_lat_key k = {.tid = tid, .id = id};
    struct sys_lat_val *sv = h_sys(&sys_lat, &k);
    if (sv) {
      sv->count++;
      sv->lat_sum += lat;
      add_hist64(sv->hist, lat);
      if (ret < 0) sv->error_count++;
    }
    struct lat_stat *st = h_lat(&sys_st, &tid);
    if (st) { st->count++; st->lat_sum += lat; add_hist13(st->hist, lat); }
  }
}

SEC("fentry/do_syscall_64")
int BPF_PROG(fentry_sys, struct pt_regs *regs, unsigned int nr) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  u64 id = BPF_CORE_READ(regs, orig_ax);
  u8 futex_wait = 0;
  if (id == ETD_NR_FUTEX) {
    unsigned long arg1 = BPF_CORE_READ(regs, si);  // x86_64: rsi = 2nd arg
    u64 cmd = arg1 & FUTEX_CMD_MASK;
    if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) futex_wait = 1;
  }
  struct sys_start_t st = {};
  st.id = (u32)id;
  st.ts = bpf_ktime_get_ns();
  st.futex_wait = futex_wait;
  bpf_map_update_elem(&sys_start, &tid, &st, BPF_ANY);
  return 0;
}

SEC("fexit/do_syscall_64")
int BPF_PROG(fexit_sys, struct pt_regs *regs, unsigned int nr) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct sys_start_t *st = bpf_map_lookup_elem(&sys_start, &tid);
  if (!st) return 0;
  u64 lat = bpf_ktime_get_ns() - st->ts;
  long ret = (long)BPF_CORE_READ(regs, ax);
  syslat_account(tid, st->id, st->futex_wait, lat, ret);
  bpf_map_delete_elem(&sys_start, &tid);
  return 0;
}

// ===========================================================================
// DEEP: raw syscalls enter/exit (fallback for non-x86 or fentry-less kernels)
SEC("tp_btf/sys_enter")
int BPF_PROG(on_sys_enter, struct pt_regs *regs, long id) {
  if (id < 0) return 0;  // compat (ia32/x32)
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;

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
  s.futex_wait = futex_wait;
  bpf_map_update_elem(&sys_start, &tid, &s, BPF_ANY);
  return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(on_sys_exit, struct pt_regs *regs, long ret) {
  (void)regs;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct sys_start_t *s = bpf_map_lookup_elem(&sys_start, &tid);
  if (!s) return 0;
  u64 lat = bpf_ktime_get_ns() - s->ts;

  syslat_account(tid, s->id, s->futex_wait, lat, ret);

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
// DEEP: hot-file I/O (fentry/fexit vfs_read, vfs_write) — sampled entry,
// measured exit. The entry saves dev/ino/path/ts only for sampled calls
// (bpf_d_path is only invoked on the sampled subset); the exit accumulates
// ACTUAL returned bytes (positive), errors (negative return) and latency.
// ===========================================================================
static __always_inline bool iofile_sampled(void) {
  u32 zero = 0;
  struct sample_rate_cfg *rc = bpf_map_lookup_elem(&sample_rate_cfg, &zero);
  u32 thresh = rc ? rc->iofile_thresh : 0;
  if (thresh == 0) return false;
  return bpf_get_prandom_u32() <= thresh;
}

static __always_inline void iofile_enter(struct file *f) {
  if (!deep_mode()) return;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return;
  if (!iofile_sampled()) return;

  struct io_start_t st = {};
  st.dev = (u32)BPF_CORE_READ(f, f_inode, i_sb, s_dev);
  st.ino = BPF_CORE_READ(f, f_inode, i_ino);
  st.ts = bpf_ktime_get_ns();
  // Path capture only for the sampled call; failure leaves an empty path
  // (dev/ino still identify the file).
  long n = bpf_d_path(&f->f_path, st.path, sizeof(st.path));
  if (n < 0) st.path[0] = 0;
  bpf_map_update_elem(&io_start, &tid, &st, BPF_ANY);
}

static __always_inline void iofile_exit(long ret) {
  if (!deep_mode()) return;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return;
  struct io_start_t *st = bpf_map_lookup_elem(&io_start, &tid);
  if (!st) return;
  u64 now = bpf_ktime_get_ns();
  u64 lat = now > st->ts ? now - st->ts : 0;

  struct io_file_key k = {};
  k.dev = st->dev;
  k.ino = st->ino;
  bpf_probe_read_kernel_str(k.path, sizeof(k.path), st->path);
  struct io_file_val *v = h_iof(&io_file, &k);
  if (v) {
    if (ret > 0) {
      v->bytes += (u64)ret;
      v->ops++;
    } else {
      v->errors++;
    }
    v->lat_sum += lat;
    add_hist13(v->hist, lat);
  }
  bpf_map_delete_elem(&io_start, &tid);
}

SEC("fentry/vfs_read")
int BPF_PROG(fentry_vfs_read, struct file *f, char *buf, size_t count, loff_t *pos) {
  (void)buf; (void)count; (void)pos;
  iofile_enter(f);
  return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(fexit_vfs_read, struct file *f, char *buf, size_t count, loff_t *pos, long ret) {
  (void)f; (void)buf; (void)count; (void)pos;
  iofile_exit(ret);
  return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(fentry_vfs_write, struct file *f, const char *buf, size_t count, loff_t *pos) {
  (void)buf; (void)count; (void)pos;
  iofile_enter(f);
  return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(fexit_vfs_write, struct file *f, const char *buf, size_t count, loff_t *pos,
             long ret) {
  (void)f; (void)buf; (void)count; (void)pos;
  iofile_exit(ret);
  return 0;
}

// ---- fallback: kprobe/kretprobe vfs_read/vfs_write (kernels where the
// verifier rejects the fentry/fexit pair at load, e.g. 5.15). Same sampling
// and measured-exit semantics; bpf_d_path is not called here (empty path +
// dev/ino identify the file). ----
static __always_inline void iofile_enter_kprobe(struct file *f) {
  if (!deep_mode()) return;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return;
  if (!iofile_sampled()) return;
  struct io_start_t st = {};
  st.dev = (u32)BPF_CORE_READ(f, f_inode, i_sb, s_dev);
  st.ino = BPF_CORE_READ(f, f_inode, i_ino);
  st.ts = bpf_ktime_get_ns();
  st.path[0] = 0;
  bpf_map_update_elem(&io_start, &tid, &st, BPF_ANY);
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(kprobe_vfs_read, struct file *f, char *buf, size_t count, loff_t *pos) {
  (void)buf; (void)count; (void)pos;
  iofile_enter_kprobe(f);
  return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(kretprobe_vfs_read, long ret) {
  iofile_exit(ret);
  return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *f, const char *buf, size_t count, loff_t *pos) {
  (void)buf; (void)count; (void)pos;
  iofile_enter_kprobe(f);
  return 0;
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(kretprobe_vfs_write, long ret) {
  iofile_exit(ret);
  return 0;
}

// ===========================================================================
// DEEP network evidence (all optional, all deep_mode + target/cookie gated)
// ===========================================================================
static __always_inline u64 sock_cookie(struct sock *sk) {
  u64 c = bpf_get_socket_cookie(sk);
  return c ? c : (u64)sk;
}

static __always_inline u32 sock_family(struct sock *sk) {
  return (u32)BPF_CORE_READ(sk, __sk_common.skc_family);
}

static __always_inline void fill_tuple(struct sock_owner_t *o, struct sock *sk) {
  o->family = sock_family(sk);
  o->local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
  o->remote_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
  if (o->family == AF_INET6) {
    __builtin_memcpy(o->local_addr,
                     (void *)BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
                     sizeof(o->local_addr));
    __builtin_memcpy(o->remote_addr,
                     (void *)BPF_CORE_READ(sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32),
                     sizeof(o->remote_addr));
  } else {
    o->local_addr[0] = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    o->remote_addr[0] = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  }
  o->netns_ino = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

// Actual socket queue bytes: tx = sk_wmem_queued; rx derived from tcp_sock
// rcv_nxt - copied_seq (sk_rmem_alloc is absent from 5.15 struct sock BTF).
static __always_inline void flow_bytes(struct sock *sk, u64 *tx, u64 *rx) {
  *tx = BPF_CORE_READ(sk, sk_wmem_queued);
  struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);
  if (tp) {
    u64 nxt = BPF_CORE_READ(tp, rcv_nxt);
    u64 cpy = BPF_CORE_READ(tp, copied_seq);
    *rx = nxt >= cpy ? nxt - cpy : 0;
  } else {
    *rx = 0;
  }
}

// kprobe/kretprobe tcp_v4/v6_connect — connect latency for target threads.
static __always_inline void tcp_connect_enter(struct sock *sk) {
  if (!deep_mode()) return;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return;
  u64 cookie = sock_cookie(sk);
  if (!cookie) return;
  struct sock_owner_t o = {};
  o.tgid = (u64)(bpf_get_current_pid_tgid() >> 32);
  o.tid = tid;
  fill_tuple(&o, sk);
  o.start_ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&sock_owner, &cookie, &o, BPF_ANY);
  struct connect_start_t cs = {.cookie = cookie, .ts = o.start_ts};
  bpf_map_update_elem(&connect_start, &tid, &cs, BPF_ANY);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk,
                                struct sockaddr *uaddr, int addr_len) {
  (void)uaddr; (void)addr_len;
  tcp_connect_enter(sk);
  return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect, int ret) {
  // recover sk from the kprobe context: kretprobe exposes regs; read from
  // entry path is not possible, so lookup connect_start via current tid.
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct connect_start_t *cs = bpf_map_lookup_elem(&connect_start, &tid);
  if (!cs) return 0;
  if (ret == 0) {
    struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cs->cookie);
    if (o) o->established_ts = bpf_ktime_get_ns();
  } else {
    struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cs->cookie);
    if (o) {
      struct sock_owner_t f = *o;
      f.rst_reason = (u32)-ret;
      bpf_map_update_elem(&net_flow, &cs->cookie, &f, BPF_ANY);
      bpf_map_delete_elem(&sock_owner, &cs->cookie);
    }
  }
  bpf_map_delete_elem(&connect_start, &tid);
  return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk,
                                struct sockaddr *uaddr, int addr_len) {
  (void)uaddr; (void)addr_len;
  tcp_connect_enter(sk);
  return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe_tcp_v6_connect, int ret) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct connect_start_t *cs = bpf_map_lookup_elem(&connect_start, &tid);
  if (!cs) return 0;
  if (ret == 0) {
    struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cs->cookie);
    if (o) o->established_ts = bpf_ktime_get_ns();
  } else {
    struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cs->cookie);
    if (o) {
      struct sock_owner_t f = *o;
      f.rst_reason = (u32)-ret;
      bpf_map_update_elem(&net_flow, &cs->cookie, &f, BPF_ANY);
      bpf_map_delete_elem(&sock_owner, &cs->cookie);
    }
  }
  bpf_map_delete_elem(&connect_start, &tid);
  return 0;
}

// kretprobe/inet_csk_accept — accepted sockets attributed to the target thread.
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, int ret) {
  if (!deep_mode()) return 0;
  u32 tid = (u32)bpf_get_current_pid_tgid();
  if (!tid_is_target(tid)) return 0;
  struct sock *sk = (struct sock *)ret;
  if (!sk) return 0;
  u64 cookie = sock_cookie(sk);
  if (!cookie) return 0;
  struct sock_owner_t o = {};
  o.tgid = (u64)(bpf_get_current_pid_tgid() >> 32);
  o.tid = tid;
  fill_tuple(&o, sk);
  o.start_ts = bpf_ktime_get_ns();
  o.established_ts = o.start_ts;
  bpf_map_update_elem(&sock_owner, &cookie, &o, BPF_ANY);
  return 0;
}

// tp_btf/inet_sock_set_state — flow start/close.
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(net_sock_state, const struct sock *sk, int oldstate, int newstate) {
  if (!deep_mode()) return 0;
  if (newstate == 2 /*TCP_SYN_SENT*/ || newstate == 1 /*TCP_ESTABLISHED*/) {
    // ownership is set by connect/accept hooks; nothing to do on SYN.
    return 0;
  }
  u64 cookie = bpf_get_socket_cookie((struct sock *)sk);
  if (!cookie) return 0;
  struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cookie);
  if (newstate == TCP_CLOSE) {
    if (o) {
      struct sock_owner_t f = *o;
      flow_bytes((struct sock *)sk, &f.tx_bytes, &f.rx_bytes);
      bpf_map_update_elem(&net_flow, &cookie, &f, BPF_ANY);
      bpf_map_delete_elem(&sock_owner, &cookie);
    } else {
      // unowned close: record an unowned aggregate flow.
      struct sock_owner_t f = {};
      f.netns_ino = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
      f.family = sock_family((struct sock *)sk);
      flow_bytes((struct sock *)sk, &f.tx_bytes, &f.rx_bytes);
      bpf_map_update_elem(&net_flow, &cookie, &f, BPF_ANY);
    }
  }
  return 0;
}

// tp_btf/tcp_retransmit_skb — owner-gated retransmit counting.
SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(net_tcp_retransmit, const struct sock *sk, const struct sk_buff *skb) {
  (void)skb;
  if (!deep_mode()) return 0;
  u64 cookie = bpf_get_socket_cookie((struct sock *)sk);
  if (!cookie) return 0;
  struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cookie);
  if (o) o->retrans++;
  return 0;
}

// tp_btf/tcp_send_reset — record reset reason on owner sockets.
SEC("tp_btf/tcp_send_reset")
int BPF_PROG(net_tcp_send_reset, const struct sock *sk, struct sk_buff *skb) {
  (void)skb;
  if (!deep_mode()) return 0;
  u64 cookie = bpf_get_socket_cookie((struct sock *)sk);
  if (!cookie) return 0;
  struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cookie);
  if (o) {
    o->rst_reason = 1;  // RST sent (reason detail not available at this tp)
    flow_bytes((struct sock *)sk, &o->tx_bytes, &o->rx_bytes);
    struct sock_owner_t f = *o;
    bpf_map_update_elem(&net_flow, &cookie, &f, BPF_ANY);
    bpf_map_delete_elem(&sock_owner, &cookie);
  }
  return 0;
}

// tp_btf/kfree_skb — unowned drop evidence aggregated by
// (netns, ifindex, reason_id). Rate-limited via net_event_sample_rate.
SEC("tp_btf/kfree_skb")
int BPF_PROG(net_kfree_skb, struct sk_buff *skb, void *location, unsigned short protocol) {
  (void)location;
  if (!deep_mode()) return 0;
  u32 zero = 0;
  struct sample_rate_cfg *rc = bpf_map_lookup_elem(&sample_rate_cfg, &zero);
  u32 rate = rc ? rc->net_rate : 0;
  if (!rate) return 0;
  struct ratelimit_t *rl = bpf_map_lookup_elem(&ratelimit, &zero);
  u64 now = bpf_ktime_get_ns();
  if (!rl) return 0;
  u64 elapsed = now > rl->last_ts[1] ? now - rl->last_ts[1] : 0;
  if (rl->last_ts[1] != 0 && elapsed * (u64)rate < 1000000000ULL) return 0;
  rl->last_ts[1] = now;

  struct net_device *dev = BPF_CORE_READ(skb, dev);
  struct net_drop_key k = {};
  k.ifindex = dev ? BPF_CORE_READ(dev, ifindex) : 0;
  // netns of the skb is unreliable without the sock; use dev netns when present.
  if (dev) k.netns_ino = BPF_CORE_READ(dev, nd_net.net, ns.inum);
  k.reason_id = protocol;
  u64 *c = h_u64(&net_drop, &k);
  if (c) (*c)++;
  return 0;
}

// tp_btf/softirq_entry + softirq_exit — per-CPU NET_RX/NET_TX count/time.
SEC("tp_btf/softirq_entry")
int BPF_PROG(net_softirq_entry, unsigned int vec_nr) {
  if (!deep_mode()) return 0;
  if (vec_nr != 3 && vec_nr != 2) return 0;  // NET_RX=3, NET_TX=2 (enum order)
  u32 zero = 0;
  u64 now = bpf_ktime_get_ns();
  bpf_map_update_elem(&softirq_enter_ts, &zero, &now, BPF_ANY);
  return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(net_softirq_exit, unsigned int vec_nr) {
  if (!deep_mode()) return 0;
  if (vec_nr != 3 && vec_nr != 2) return 0;
  u32 zero = 0;
  u64 *ts = bpf_map_lookup_elem(&softirq_enter_ts, &zero);
  if (!ts || *ts == 0) return 0;
  u64 now = bpf_ktime_get_ns();
  u64 dur = now > *ts ? now - *ts : 0;
  *ts = 0;
  u32 cpu = bpf_get_smp_processor_id();
  struct net_softirq_key k = {.cpu_idx = cpu, .vector = vec_nr};
  struct lat_stat *v = h_lat(&net_softirq, &k);
  if (v) { v->count++; v->lat_sum += dur; add_hist13(v->hist, dur); }
  return 0;
}

// kprobe/tcp_rcv_established — sampled RTT (srtt_us>>3), owner sockets only,
// per-socket rate limit via rtt_last.
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock *sk,
                                struct sk_buff *skb) {
  (void)skb;
  if (!deep_mode()) return 0;
  u64 cookie = bpf_get_socket_cookie(sk);
  if (!cookie) return 0;
  struct sock_owner_t *o = bpf_map_lookup_elem(&sock_owner, &cookie);
  if (!o) return 0;
  u32 zero = 0;
  struct sample_rate_cfg *rc = bpf_map_lookup_elem(&sample_rate_cfg, &zero);
  u32 rate = rc ? rc->net_rate : 0;
  if (!rate) return 0;
  u64 now = bpf_ktime_get_ns();
  u64 *last = bpf_map_lookup_elem(&rtt_last, &cookie);
  if (last) {
    u64 elapsed = now > *last ? now - *last : 0;
    if (elapsed * (u64)rate < 1000000000ULL) return 0;
  }
  struct tcp_sock *tp = bpf_skc_to_tcp_sock(sk);
  if (!tp) return 0;
  u64 srtt = BPF_CORE_READ(tp, srtt_us);  // RTT in 8us units
  o->rtt_count++;
  o->rtt_sum_us += (srtt >> 3);
  if (last)
    *last = now;
  else
    bpf_map_update_elem(&rtt_last, &cookie, &now, BPF_ANY);
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