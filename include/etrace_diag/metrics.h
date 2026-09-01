#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Shared metric record schemas. Every emitted record is JSON Lines with "v":2.
// BPF kernel structs (see bpf/etrace.bpf.c) mirror CanonicalSnapshot's layout;
// field order/sizes are frozen and must match snapshot_rec.
//
// Presence convention: a metric that exists but could not be read is
// represented by valid=false in JSON and NULL in SQLite; zero is ONLY a real
// measured zero. Presence bits are fixed (see each struct).

namespace etrace_diag {

constexpr int kBase4HistBins = 13;   // base-4 log2 latency histogram bins
constexpr int kLog2HistBins = 64;    // bpf_log2l-style latency histogram bins
using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

struct ProcessRow {
  uint32_t pid = 0;
  uint32_t tgid = 0;
  uint8_t state = 0;
  uint64_t start_time = 0;
  uint64_t utime = 0;
  uint64_t stime = 0;
  uint64_t nvcsw = 0;
  uint64_t nivcsw = 0;
  uint64_t minflt = 0;     // from iter/task (task_struct.min_flt)
  uint64_t majflt = 0;     // from iter/task (task_struct.maj_flt)
  uint64_t total_vm = 0;   // pages, from iter (mm->total_vm)
  // ---- fine-grained fields, ALL sourced from the single iter/task pass ----
  uint64_t rchar = 0, wchar = 0;            // task_struct.ioac (cumulative)
  uint64_t syscr = 0, syscw = 0;
  uint64_t read_bytes = 0, write_bytes = 0;
  uint64_t sum_exec_runtime_ns = 0;         // task_struct.se.sum_exec_runtime
  uint64_t run_delay_ns = 0;                // task_struct.sched_info.run_delay
  uint64_t rss_anon_pages = 0;              // mm->rss_stat.count[MM_ANONPAGES]
  uint64_t rss_file_pages = 0;              // mm->rss_stat.count[MM_FILEPAGES]
  uint64_t rss_shmem_pages = 0;             // mm->rss_stat.count[MM_SHMEMPAGES]
  uint64_t swap_ents = 0;                   // mm->rss_stat.count[MM_SWAPENTS]
  uint64_t rss_kb = 0;                      // derived: (anon+file+shmem)*4
  bool rss_valid = false;
  bool ioac_valid = false;                  // false when CO-RE lacks task.ioac
  bool sched_valid = false;                 // false when se/sched_info missing
  char comm[16] = {0};
};

void to_json(nlohmann::json& j, const ProcessRow& r);

struct CpuStat {
  uint64_t user = 0, nice = 0, system = 0, idle = 0;
  uint64_t iowait = 0, irq = 0, softirq = 0, steal = 0;
  uint64_t guest = 0, guest_nice = 0;
};

struct LoadAvg {
  double load1 = 0, load5 = 0, load15 = 0;
  uint32_t nr_running = 0;   // run-queue length evidence (4th loadavg field)
  uint32_t nr_threads = 0;
};

// Presence bits (fixed): bit0..7 = mem_total, mem_available, mem_free, buffers,
// cached, swap_total, swap_free, anon_pages; bit8..13 = sreclaimable, shmem,
// dirty, writeback, commit_limit, committed_as.
struct MemInfo {
  uint64_t mem_total_kb = 0;
  uint64_t mem_available_kb = 0;
  uint64_t mem_free_kb = 0;
  uint64_t buffers_kb = 0;
  uint64_t cached_kb = 0;
  uint64_t swap_total_kb = 0;
  uint64_t swap_free_kb = 0;
  uint64_t anon_pages_kb = 0;
  uint64_t sreclaimable_kb = 0;
  uint64_t shmem_kb = 0;
  uint64_t dirty_kb = 0;
  uint64_t writeback_kb = 0;
  uint64_t commit_limit_kb = 0;
  uint64_t committed_as_kb = 0;
  uint32_t valid_mask = 0;
};

// Presence bits (fixed): bit0..3 = pgfault, pgmajfault, pswpin, pswpout;
// bit4..10 = pgscan_kswapd, pgscan_direct, pgsteal_kswapd, pgsteal_direct,
// workingset_refault, nr_dirty, nr_writeback.
// NOTE: nr_free_pages / nr_anon_pages are removed from the v2 contract
// (redundant with MemInfo.mem_free_kb / anon_pages_kb).
struct VmStatSnapshot {
  uint64_t pgfault = 0;
  uint64_t pgmajfault = 0;
  uint64_t pswpin = 0;
  uint64_t pswpout = 0;
  uint64_t pgscan_kswapd = 0;
  uint64_t pgscan_direct = 0;
  uint64_t pgsteal_kswapd = 0;
  uint64_t pgsteal_direct = 0;
  uint64_t workingset_refault = 0;
  uint64_t nr_dirty = 0;
  uint64_t nr_writeback = 0;
  uint32_t valid_mask = 0;
};

// One PSI level ("some" or "full"): avg10/avg60/avg300 percentages. Valid
// flags distinguish "file/line missing" from a real 0.
struct PsiWindow {
  double avg10 = 0, avg60 = 0, avg300 = 0;
  bool some_valid = false;
  bool full_valid = false;
};

// Per-resource two-level PSI. CPU exposes only `some` in practice (no full
// line in /proc/pressure/cpu); memory/io carry both levels when present.
struct PsiSnapshot {
  PsiWindow cpu, io, memory;
};

// Presence bits (fixed): bit0..6 = reads_completed, reads_merged,
// sectors_read, read_ticks_ms, writes_completed, writes_merged,
// sectors_written... exact order per iostats: bit0 reads_completed, bit1
// reads_merged, bit2 sectors_read, bit3 read_ticks_ms, bit4 writes_completed,
// bit5 writes_merged, bit6 sectors_written, bit7 write_ticks_ms,
// bit8 in_flight, bit9 io_ticks_ms, bit10 weighted_ticks_ms.
struct DiskStatRow {
  uint32_t major = 0, minor = 0;
  char name[32] = {0};
  uint64_t reads_completed = 0;
  uint64_t reads_merged = 0;
  uint64_t sectors_read = 0;
  uint64_t read_ticks_ms = 0;
  uint64_t writes_completed = 0;
  uint64_t writes_merged = 0;
  uint64_t sectors_written = 0;
  uint64_t write_ticks_ms = 0;
  uint64_t ios_in_flight = 0;
  uint64_t io_ticks_ms = 0;
  uint64_t weighted_ticks_ms = 0;
  uint32_t valid_mask = 0;
};

struct HostSnapshot {
  uint64_t ts_ns = 0;
  std::vector<CpuStat> cpus;
  CpuStat total;
  LoadAvg load;
  MemInfo mem;
  VmStatSnapshot vm;
  PsiSnapshot psi;
  std::vector<DiskStatRow> disks;
  std::vector<ProcessRow> procs;  // top tasks from iter/task
  // /proc/stat system-wide counters (ctxt = context switches since boot).
  uint64_t ctxt = 0;
  uint64_t processes = 0;        // forks since boot
  uint64_t procs_running = 0;    // runnable tasks right now
  uint64_t procs_blocked = 0;    // tasks blocked on I/O right now
};

void to_json(nlohmann::json& j, const HostSnapshot& s);

// ---------------------------------------------------------------------------
// BASE network
// ---------------------------------------------------------------------------

// One network interface's cumulative counters (rtnl_link_stats64 semantics).
// `valid` is false when the interface row could not be read (e.g. netlink
// failure and missing /proc/net/dev fallback).
struct NetInterfaceRow {
  uint32_t ifindex = 0;
  std::string name;
  std::string source;       // "netlink" | "fallback"
  int32_t operstate = -1;   // IF_OPER_UNKNOWN = -1 when missing
  uint32_t mtu = 0;
  uint64_t rx_bytes = 0;
  uint64_t rx_packets = 0;
  uint64_t rx_errors = 0;
  uint64_t rx_dropped = 0;
  uint64_t tx_bytes = 0;
  uint64_t tx_packets = 0;
  uint64_t tx_errors = 0;
  uint64_t tx_dropped = 0;
  uint64_t collisions = 0;
  uint64_t carrier_changes = 0;
  uint64_t rx_nohandler = 0;
  bool valid = false;
  std::string error;
};

// Protocol-stack snapshot for the collector's network namespace. Counters are
// cumulative since boot; TCP state / queue summaries come from
// NETLINK_INET_DIAG (NULL when the dump fails, distinguished from a real 0).
struct NetStackSnapshot {
  uint64_t ts_ns = 0;
  uint64_t netns_ino = 0;   // 0 = unknown/unreadable
  std::string source;       // "procfs" | "netlink" | "mixed" | "fallback"
  bool valid = false;
  std::string error;
  // /proc/net/snmp Tcp
  uint64_t active_opens = 0;
  uint64_t passive_opens = 0;
  uint64_t attempt_fails = 0;
  uint64_t estab_resets = 0;
  uint64_t curr_estab = 0;
  uint64_t in_segs = 0;
  uint64_t out_segs = 0;
  uint64_t retrans_segs = 0;
  uint64_t in_errs = 0;
  uint64_t out_rsts = 0;
  // /proc/net/netstat TcpExt (selected high-signal fields)
  uint64_t listen_overflows = 0;
  uint64_t listen_drops = 0;
  uint64_t backlog_drop = 0;
  uint64_t rcv_q_drop = 0;
  uint64_t syn_retrans = 0;
  uint64_t timeouts = 0;
  uint64_t memory_pressures = 0;
  // /proc/net/snmp Udp
  uint64_t udp_in_datagrams = 0;
  uint64_t udp_no_ports = 0;
  uint64_t udp_in_errors = 0;
  uint64_t udp_out_datagrams = 0;
  uint64_t udp_rcvbuf_errors = 0;
  uint64_t udp_sndbuf_errors = 0;
  // /proc/net/sockstat(+6) socket pressure
  uint64_t tcp_sock_mem = 0;    // pages of TCP socket memory
  uint64_t udp_sock_mem = 0;    // pages of UDP socket memory
  uint64_t frag_sock_mem = 0;   // fragment memory pressure count
  // NETLINK_INET_DIAG TCP state summary (valid when the dump succeeded)
  uint64_t tcp_state_established = 0;
  uint64_t tcp_state_syn_sent = 0;
  uint64_t tcp_state_syn_recv = 0;
  uint64_t tcp_state_fin_wait1 = 0;
  uint64_t tcp_state_fin_wait2 = 0;
  uint64_t tcp_state_time_wait = 0;
  uint64_t tcp_state_close = 0;
  uint64_t tcp_state_close_wait = 0;
  uint64_t tcp_state_last_ack = 0;
  uint64_t tcp_state_listen = 0;
  uint64_t tcp_state_closing = 0;
  uint64_t rqueue_bytes = 0;
  uint64_t wqueue_bytes = 0;
  bool tcp_states_valid = false;
};

struct NetSoftnetRow {
  uint32_t cpu_idx = 0;
  uint64_t processed = 0;
  uint64_t dropped = 0;
  uint64_t time_squeeze = 0;
  uint64_t received_rps = 0;
  uint64_t flow_limit_count = 0;
  uint64_t backlog_len = 0;      // input_pkt_queue + process_queue
  uint64_t net_rx_softirq = 0;   // /proc/softirqs NET_RX
  uint64_t net_tx_softirq = 0;   // /proc/softirqs NET_TX
  bool valid = false;
  std::string error;
};

struct NetworkSnapshot {
  uint64_t ts_ns = 0;
  bool enabled = true;          // devices.network_enabled
  NetStackSnapshot stack;
  std::vector<NetInterfaceRow> ifaces;
  std::vector<NetSoftnetRow> softnets;
};

void to_json(nlohmann::json& j, const NetworkSnapshot& s);

// ---------------------------------------------------------------------------
// BASE cgroup (collector's own cgroup v2 directory only)
// ---------------------------------------------------------------------------

struct CgroupIOStat {
  uint32_t major = 0;
  uint32_t minor = 0;
  uint64_t rbytes = 0;
  uint64_t wbytes = 0;
  uint64_t rios = 0;
  uint64_t wios = 0;
  uint64_t dbytes = 0;   // discarded bytes (cgroup v2 io.stat)
  uint64_t dios = 0;
};

struct CgroupSnapshot {
  uint64_t ts_ns = 0;
  bool available = false;   // false = cgroup v1 / unreadable
  std::string cgroup_path;
  std::string error;
  // cpu.stat
  uint64_t cpu_usage_usec = 0;
  uint64_t user_usec = 0;
  uint64_t system_usec = 0;
  uint64_t nr_periods = 0;
  uint64_t nr_throttled = 0;
  uint64_t throttled_usec = 0;
  bool cpu_valid = false;
  // memory.current / memory.max / memory.events
  uint64_t memory_current_bytes = 0;
  uint64_t memory_max_bytes = 0;
  bool memory_max_unlimited = false;
  uint64_t memory_events_low = 0;
  uint64_t memory_events_high = 0;
  uint64_t memory_events_max = 0;
  uint64_t memory_events_oom = 0;
  uint64_t memory_events_oom_kill = 0;
  bool memory_valid = false;
  // cpu.pressure / memory.pressure (two-level PSI)
  PsiWindow cpu_psi;
  PsiWindow memory_psi;
  std::vector<CgroupIOStat> io;
};

void to_json(nlohmann::json& j, const CgroupSnapshot& s);

// ---------------------------------------------------------------------------
// BASE GPU
// ---------------------------------------------------------------------------

// Numeric valid bits (fixed): bit0 util, bit1 mem_util, bit2/3 mem used/total,
// bit4 temp, bit5/6 power/limit, bit7 energy, bit8/9 clocks, bit10/11 PCIe
// RX/TX, bit12/13 encoder/decoder, bit14 throttle, bit15/16 ECC SBE/DBE,
// bit17 retired pages.
struct GpuDeviceRow {
  std::string uuid;         // NVML UUID / sysfs path / "disabled" / "unavailable"
  std::string pci_bdf;      // e.g. "0000:01:00.0"
  std::string vendor;       // "nvidia" | "amd" | "intel" | ""
  std::string model;        // NVML name / DRM model, best-effort
  std::string source;       // "nvml" | "drm" | "off"
  bool available = false;
  bool is_mig = false;
  double util_pct = 0;         // gpu busy percent [0,100]
  double mem_util_pct = 0;     // [0,100]
  uint64_t mem_used_bytes = 0;
  uint64_t mem_total_bytes = 0;
  double temperature_c = 0;
  double power_w = 0;
  double power_limit_w = 0;
  uint64_t energy_mj = 0;
  uint32_t sm_clock_mhz = 0;
  uint32_t mem_clock_mhz = 0;
  uint64_t pcie_rx_kbps = 0;
  uint64_t pcie_tx_kbps = 0;
  double encoder_util_pct = 0;
  double decoder_util_pct = 0;
  uint64_t throttle_reasons = 0;
  uint64_t ecc_sbe_total = 0;
  uint64_t ecc_dbe_total = 0;
  uint64_t retired_pages = 0;
  uint32_t error_code = 0;    // provider error code (0 = none)
  std::string error_text;
  uint32_t valid_mask = 0;
};

struct GpuSnapshot {
  uint64_t ts_ns = 0;
  std::vector<GpuDeviceRow> devices;
};

void to_json(nlohmann::json& j, const GpuSnapshot& s);

// Per-tid cumulative counters aggregated host-side for the anomaly feature
// vector. Mirrors the kernel PERCPU_HASH counter set (summed per tid).
struct EbpfPerTidStats {
  uint32_t tid = 0;
  uint64_t on_cpu_ns = 0;
  uint64_t nr_sw_vol = 0;
  uint64_t nr_sw_invol = 0;
  uint64_t io_ops = 0;
  uint64_t io_bytes = 0;
  uint64_t pf_minor = 0;
  uint64_t pf_major = 0;
  uint64_t lock_waits = 0;
  uint64_t lock_lat_ns = 0;
};

struct EbpfCounters {
  uint64_t ts_ns = 0;
  // Aggregates across current target tids (cumulative).
  uint64_t on_cpu_ns_total = 0;
  uint64_t switch_total = 0;
  uint64_t io_ops_total = 0;
  uint64_t io_bytes_total = 0;
  uint64_t minor_faults_total = 0;
  uint64_t major_faults_total = 0;
  uint64_t lock_waits_total = 0;
  std::vector<EbpfPerTidStats> per_tid;
};

void to_json(nlohmann::json& j, const EbpfCounters& c);

// ---------------------------------------------------------------------------
// DEEP evidence rows (independent of the flight-recorder ring)
// ---------------------------------------------------------------------------

// Target /proc/<tid> status/io/schedstat sampled once per deep_dump_interval.
// available=false when /proc/<tid> itself was unreadable; per-file failures
// leave only the corresponding fields NULL.
struct DeepProcessRow {
  int ordinal = 0;
  uint64_t ts_ns = 0;
  uint32_t tid = 0;
  uint32_t tgid = 0;
  std::string comm;
  // /proc/<tid>/status
  uint64_t vm_rss_kb = 0;
  uint64_t rss_anon_kb = 0;
  uint64_t rss_file_kb = 0;
  uint64_t rss_shmem_kb = 0;
  uint64_t vm_swap_kb = 0;
  bool status_valid = false;
  // /proc/<tid>/io (cumulative)
  uint64_t rchar = 0;
  uint64_t wchar = 0;
  uint64_t read_bytes = 0;
  uint64_t write_bytes = 0;
  uint64_t syscr = 0;
  uint64_t syscw = 0;
  bool io_valid = false;
  // /proc/<tid>/schedstat (cumulative)
  uint64_t sched_exec_runtime_ns = 0;
  uint64_t sched_run_delay_ns = 0;
  uint64_t sched_switch_count = 0;
  bool sched_valid = false;
  bool available = false;
  std::string error;
};

void to_json(nlohmann::json& j, const DeepProcessRow& r);

struct DeepIoDeviceRow {
  int ordinal = 0;
  uint32_t dev = 0;
  uint64_t ops = 0;
  uint64_t bytes = 0;
  uint64_t lat_sum = 0;              // ns
  uint32_t hist[kBase4HistBins] = {0};
  float p50_us = 0;
  float p99_us = 0;
};

void to_json(nlohmann::json& j, const DeepIoDeviceRow& r);

// Stackless off-CPU wait aggregated per tid (stack_available=0 sample path).
struct DeepOffcpuRow {
  int ordinal = 0;
  uint32_t tid = 0;
  uint32_t tgid = 0;
  std::string comm;
  uint64_t dwell_ns = 0;
  uint64_t count = 0;
  int stack_available = 0;
};

void to_json(nlohmann::json& j, const DeepOffcpuRow& r);

// One observed TCP connection/flow attributed to a target socket.
struct DeepNetFlowRow {
  int ordinal = 0;
  uint64_t cookie = 0;
  uint32_t tgid = 0;
  uint32_t tid = 0;
  uint64_t netns_ino = 0;
  uint32_t family = 0;             // AF_INET=2 / AF_INET6=10
  uint64_t local_addr = 0;         // 4-byte IPv4 or 16-byte IPv6 (first 8B for row)
  uint32_t local_port = 0;
  uint64_t remote_addr = 0;
  uint32_t remote_port = 0;
  uint32_t final_state = 0;        // TCP_CLOSE etc
  uint64_t start_ts_ns = 0;
  uint64_t established_ts_ns = 0;
  uint64_t end_ts_ns = 0;
  uint64_t duration_us = 0;
  uint64_t connect_latency_us = 0;
  uint64_t tx_bytes = 0;
  uint64_t rx_bytes = 0;
  uint64_t retransmits = 0;
  uint32_t rst_reason = 0;
  uint64_t rtt_count = 0;
  uint64_t rtt_avg_us = 0;
  uint64_t rtt_p50_us = 0;
  uint64_t rtt_p99_us = 0;
  bool closed = false;
  bool owner_available = false;    // false = unowned aggregate
  std::string error;
};

void to_json(nlohmann::json& j, const DeepNetFlowRow& r);

struct DeepNetDropRow {
  int ordinal = 0;
  uint64_t netns_ino = 0;
  uint32_t ifindex = 0;
  uint32_t reason_id = 0;
  std::string reason;
  uint64_t count = 0;
};

void to_json(nlohmann::json& j, const DeepNetDropRow& r);

struct DeepNetSoftirqRow {
  int ordinal = 0;
  uint32_t cpu_idx = 0;
  uint32_t vector = 0;             // NET_RX / NET_TX enum value
  std::string vector_name;
  uint64_t count = 0;
  uint64_t time_ns = 0;
  std::string hist;                // JSON histogram text
};

void to_json(nlohmann::json& j, const DeepNetSoftirqRow& r);

// Per-target process GPU evidence (NVML process queries aligned by tgid).
struct DeepGpuProcessRow {
  int ordinal = 0;
  uint64_t ts_ns = 0;
  std::string gpu_uuid;
  uint32_t pid = 0;
  uint32_t tgid = 0;
  std::string comm;
  std::string source;              // "nvml" | "drm" | "off"
  double sm_util_pct = 0;
  double mem_util_pct = 0;
  double enc_util_pct = 0;
  double dec_util_pct = 0;
  uint64_t fb_used_bytes = 0;
  uint64_t source_ts_us = 0;       // provider's own timestamp (us)
  uint32_t valid_mask = 0;         // bit0 sm, bit1 mem, bit2 enc, bit3 dec, bit4 fb
  std::string error;
};

void to_json(nlohmann::json& j, const DeepGpuProcessRow& r);

// Per-BPF-program execution statistics. Populated via BPF_OBJ_GET_INFO_BY_FD;
// kernel.bpf_stats_enabled must be 1 for run_cnt/run_time_ns to be non-zero.
struct BpfProgStats {
  std::string name;
  uint32_t id = 0;
  uint64_t run_cnt = 0;
  uint64_t run_time_ns = 0;
};

struct BpfStatsSnapshot {
  uint64_t ts_ns = 0;
  uint64_t interval_ns = 0;   // wall-clock delta since the previous sample
  bool stats_enabled = false;  // kernel.bpf_stats_enabled honored at startup
  std::vector<BpfProgStats> progs;
};

// User-space collector process self overhead (RUSAGE_SELF + /proc/self/status).
struct ProcOverhead {
  uint64_t ts_ns = 0;
  uint64_t utime_ns = 0;    // cumulative CPU user time
  uint64_t stime_ns = 0;    // cumulative CPU kernel time
  uint64_t nvcsw = 0;       // cumulative voluntary context switches
  uint64_t nivcsw = 0;      // cumulative involuntary context switches
  uint64_t minflt = 0;      // cumulative minor page faults
  uint64_t majflt = 0;      // cumulative major page faults
  uint64_t rss_kb = 0;      // instantaneous VmRSS
  uint64_t vmhwm_kb = 0;    // high-water mark VmHWM
};

void to_json(nlohmann::json& j, const BpfProgStats& s);
void to_json(nlohmann::json& j, const BpfStatsSnapshot& s);
void to_json(nlohmann::json& j, const ProcOverhead& s);

// One flight-recorder record = one target @ one tick. Cumulative counters are
// never reset in-kernel; deltas are computed by downstream consumers.
struct CanonicalSnapshot {
  uint64_t ts_ns = 0;
  uint32_t tgid = 0;
  uint32_t tid = 0;
  char comm[16] = {0};
  // BASE (always-on)
  uint64_t on_cpu_ns = 0;
  uint32_t nr_sw_vol = 0;
  uint32_t nr_sw_invol = 0;
  uint64_t io_ops = 0;
  uint64_t io_bytes = 0;
  uint32_t io_hist[kBase4HistBins] = {0};
  uint32_t pf_minor = 0;
  uint32_t pf_major = 0;
  uint64_t lock_waits = 0;
  uint64_t lock_lat_ns = 0;
  uint32_t lock_hist[kBase4HistBins] = {0};
  // DEEP-gated (0 during BASE)
  uint64_t syscall_count = 0;
  uint64_t syscall_lat_ns = 0;
  uint32_t syscall_hist[kBase4HistBins] = {0};
  uint64_t futex_waits = 0;
  uint64_t futex_lat_ns = 0;
  uint32_t futex_hist[kBase4HistBins] = {0};
  uint64_t runq_wait_ns = 0;
  uint32_t runq_wait_count = 0;
  uint32_t runq_hist[kBase4HistBins] = {0};
  uint32_t flags = 0;  // bit0 = deep-mode tick
};

void to_json(nlohmann::json& j, const CanonicalSnapshot& s);

}  // namespace etrace_diag
