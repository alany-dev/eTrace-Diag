#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// Shared metric record schemas. Every emitted record is JSON Lines with "v":1.
// BPF kernel structs (see bpf/etrace.bpf.c) mirror CanonicalSnapshot's layout;
// field order/sizes are frozen and must match snapshot_rec.

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
  uint64_t total_vm = 0;   // pages, from iter (mm->total_vm)
  uint64_t rss_kb = 0;     // host-filled from /proc/<pid>/status (targets only)
  char comm[16] = {0};
};

void to_json(nlohmann::json& j, const ProcessRow& r);

struct CpuStat {
  uint64_t user = 0, nice = 0, system = 0, idle = 0;
  uint64_t iowait = 0, irq = 0, softirq = 0, steal = 0;
};

struct LoadAvg {
  double load1 = 0, load5 = 0, load15 = 0;
  uint32_t nr_running = 0;   // run-queue length evidence (4th loadavg field)
  uint32_t nr_threads = 0;
};

struct MemInfo {
  uint64_t mem_total_kb = 0;
  uint64_t mem_available_kb = 0;
  uint64_t mem_free_kb = 0;
  uint64_t buffers_kb = 0;
  uint64_t cached_kb = 0;
  uint64_t swap_total_kb = 0;
  uint64_t swap_free_kb = 0;
  uint64_t anon_pages_kb = 0;
};

struct VmStatSnapshot {
  uint64_t pgfault = 0;
  uint64_t pgmajfault = 0;
  uint64_t pswpin = 0;
  uint64_t pswpout = 0;
  uint64_t nr_free_pages = 0;
  uint64_t nr_anon_pages = 0;
};

struct PsiSnapshot {   // "full" PSI (all tasks) avg10/60/300
  double cpu10 = 0, cpu60 = 0, cpu300 = 0;
  double io10 = 0, io60 = 0, io300 = 0;
  double mem10 = 0, mem60 = 0, mem300 = 0;
};

struct DiskStatRow {
  uint32_t major = 0, minor = 0;
  char name[32] = {0};
  uint64_t reads_completed = 0;
  uint64_t writes_completed = 0;
  uint64_t sectors_read = 0;
  uint64_t sectors_written = 0;
  uint64_t io_ticks_ms = 0;
  uint64_t read_ticks_ms = 0;
  uint64_t write_ticks_ms = 0;
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
};

void to_json(nlohmann::json& j, const HostSnapshot& s);

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
  // Aggregates across all tracked tids (cumulative).
  uint64_t on_cpu_ns_total = 0;
  uint64_t switch_total = 0;
  uint64_t io_ops_total = 0;
  uint64_t io_bytes_total = 0;
  uint64_t faults_total = 0;
  uint64_t lock_waits_total = 0;
  std::vector<EbpfPerTidStats> per_tid;
};

void to_json(nlohmann::json& j, const EbpfCounters& c);
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