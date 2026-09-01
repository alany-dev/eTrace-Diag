#pragma once

// Single source of truth for C++ mirrors of BPF map value structs.
// Every consumer (app, target_selector, deep_collector, ebpf_manager,
// map_reader) references these instead of redeclaring layouts. Each mirror
// documents the kernel struct it must match; runtime size checks happen where
// maps are opened.
#include <cstdint>

namespace etrace_diag {

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

constexpr int kHist13Bins = 13;   // must match HIST13_BINS in etrace.bpf.c
constexpr int kHist64Bins = 64;   // must match HIST64_BINS in etrace.bpf.c

// struct switch_t { u32 vol; u32 invol; }
struct SwitchVal {
  u32 vol;
  u32 invol;
};

// struct blk_io_t { u64 ops; u64 bytes; u64 lat_sum; u32 hist[13]; }
struct BlockIoVal {
  u64 ops;
  u64 bytes;
  u64 lat_sum;
  u32 hist[kHist13Bins];
};

// struct faults_t { u32 minor; u32 major; }
struct FaultsVal {
  u32 minor;
  u32 major;
};

// struct lat_stat { u64 count; u64 lat_sum; u32 hist[13]; }
struct LatStatVal13 {
  u64 count;
  u64 lat_sum;
  u32 hist[kHist13Bins];
};

// struct mem_events_t { u32 kswapd_active; u32 direct_reclaim; u64 nr_reclaimed; }
struct MemEventsVal {
  u32 kswapd_active;
  u32 direct_reclaim;
  u64 nr_reclaimed;
};

// struct oom_event_t { u64 ts; u32 pid; }
struct OomEventVal {
  u64 ts;
  u32 pid;
};

// struct sys_lat_val { u64 count; u64 lat_sum; u64 error_count; u32 hist[64]; }
struct SysLatVal {
  u64 count;
  u64 lat_sum;
  u64 error_count;
  u32 hist[kHist64Bins];
};

// struct sys_lat_key { u32 tid; u32 id; }
struct SysLatKey {
  u32 tid;
  u32 id;
};

// struct oncpu_key { u32 pid; u32 tid; u32 user_sid; u32 kernel_sid; }
struct OncpuKey {
  u32 pid;
  u32 tid;
  u32 user_sid;
  u32 kernel_sid;
};

// struct io_file_key { u32 dev; u64 ino; char path[256]; }
struct IoFileKey {
  u32 dev;
  u64 ino;
  char path[256];
};

// struct io_file_val { u64 bytes; u32 ops; u64 errors; u64 lat_sum;
//                      u32 hist[13]; }
struct IoFileVal {
  u64 bytes;
  u32 ops;
  u64 errors;
  u64 lat_sum;
  u32 hist[kHist13Bins];
};

// struct io_start_t { u32 dev; u64 ino; char path[256]; u64 ts; }
struct IoStartVal {
  u32 dev;
  u64 ino;
  char path[256];
  u64 ts;
};

// struct lock_hot_val { u64 count; u64 lat_sum; }
struct LockHotVal {
  u64 count;
  u64 lat_sum;
};

// struct offcpu_stash_t { u64 out_ts; u32 ksid; u32 stack_available; }
struct OffcpuStashVal {
  u64 out_ts;
  u32 ksid;
  u32 stack_available;
};

// struct task_meta_t { u32 tgid; u8 comm[16]; }
struct TaskMetaVal {
  u32 tgid;
  u8 comm[16];
};

// struct sock_owner_t { u64 tgid; u32 tid; u64 netns_ino; u32 family;
//   u32 local_addr[4]; u32 remote_addr[4]; u32 local_port; u32 remote_port;
//   u64 start_ts; u64 established_ts; u64 tx_bytes; u64 rx_bytes;
//   u64 retrans; u32 rst_reason; u64 rtt_count; u64 rtt_sum_us; }
struct SockOwnerVal {
  u64 tgid;
  u32 tid;
  u64 netns_ino;
  u32 family;
  u32 local_addr[4];
  u32 remote_addr[4];
  u32 local_port;
  u32 remote_port;
  u64 start_ts;
  u64 established_ts;
  u64 tx_bytes;
  u64 rx_bytes;
  u64 retrans;
  u32 rst_reason;
  u64 rtt_count;
  u64 rtt_sum_us;
};

// struct net_drop_key { u64 netns_ino; u32 ifindex; u32 reason_id; }
struct NetDropKeyVal {
  u64 netns_ino;
  u32 ifindex;
  u32 reason_id;
};

// struct net_softirq_key { u32 cpu_idx; u32 vector; }
struct NetSoftirqKeyVal {
  u32 cpu_idx;
  u32 vector;
};

}  // namespace etrace_diag
