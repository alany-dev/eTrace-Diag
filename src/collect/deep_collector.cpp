#include "collect/deep_collector.h"

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <unordered_map>
#include <utility>

#include "collect/bpf_values.h"
#include "collect/host_metrics.h"
#include "logging.h"

namespace etrace_diag {

namespace {

// Sum one record's counters/histograms into another (per-CPU merge support).
void AddSnap(KernelSnapshotRec& dst, const KernelSnapshotRec& src) {
  dst.on_cpu_ns += src.on_cpu_ns;
  dst.nr_sw_vol += src.nr_sw_vol;
  dst.nr_sw_invol += src.nr_sw_invol;
  dst.io_ops += src.io_ops;
  dst.io_bytes += src.io_bytes;
  for (int i = 0; i < kBase4HistBins; i++) dst.io_hist[i] += src.io_hist[i];
  dst.pf_minor += src.pf_minor;
  dst.pf_major += src.pf_major;
  dst.lock_waits += src.lock_waits;
  dst.lock_lat_ns += src.lock_lat_ns;
  for (int i = 0; i < kBase4HistBins; i++) dst.lock_hist[i] += src.lock_hist[i];
  dst.syscall_count += src.syscall_count;
  dst.syscall_lat_ns += src.syscall_lat_ns;
  for (int i = 0; i < kBase4HistBins; i++) dst.syscall_hist[i] += src.syscall_hist[i];
  dst.futex_waits += src.futex_waits;
  dst.futex_lat_ns += src.futex_lat_ns;
  for (int i = 0; i < kBase4HistBins; i++) dst.futex_hist[i] += src.futex_hist[i];
  dst.runq_wait_ns += src.runq_wait_ns;
  dst.runq_wait_count += src.runq_wait_count;
  for (int i = 0; i < kBase4HistBins; i++) dst.runq_hist[i] += src.runq_hist[i];
  if (src.ts_ns > dst.ts_ns) dst.ts_ns = src.ts_ns;
  dst.flags |= src.flags;
}

// Group per-CPU records of one logical tick per tid into summed records. Two
// CPUs' samples for the same tick fall within the same interval-Ns bucket.
std::vector<KernelSnapshotRec> MergePerCpu(std::vector<KernelSnapshotRec> in,
                                           uint64_t interval_ms) {
  uint64_t ns_per_tick = interval_ms * 1000000ULL;
  if (ns_per_tick == 0) ns_per_tick = 100000000ULL;
  std::map<std::pair<u32, u64>, KernelSnapshotRec> groups;
  for (auto& r : in) {
    u64 bucket = r.ts_ns / ns_per_tick;
    auto key = std::make_pair(r.tid, bucket);
    auto it = groups.find(key);
    if (it == groups.end())
      groups[key] = r;
    else
      AddSnap(it->second, r);
  }
  std::vector<KernelSnapshotRec> out;
  out.reserve(groups.size());
  for (auto& kv : groups) out.push_back(kv.second);
  std::sort(out.begin(), out.end(),
            [](const KernelSnapshotRec& a, const KernelSnapshotRec& b) { return a.ts_ns < b.ts_ns; });
  return out;
}

std::string SanitizeCommStr(const char* comm, size_t n) {
  std::string s;
  for (size_t i = 0; i < n && comm[i]; ++i) {
    char c = comm[i];
    s += (c == ';' || c == '/' || c == ' ' || c == '\t') ? '_' : c;
  }
  return s;
}

uint64_t NowNs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

}  // namespace


DeepCollector::DeepCollector(EbpfManager& ebpf, OutputWriter& writer, GpuMetrics& gpu)
    : ebpf_(ebpf), writer_(writer), gpu_(gpu) {
  stack_buf_.resize(127);
}

bool DeepCollector::Enter(int ordinal, uint64_t anomaly_start_ns, const Config& cfg) {
  ordinal_ = ordinal;
  anomaly_start_ns_ = anomaly_start_ns;
  pre_interval_ms_ = cfg.sample.fine_interval_ms;
  post_interval_ms_ = cfg.sample.deep_fine_interval_ms;
  next_dump_ns_ = 0;
  next_gpu_ns_ = 0;
  fold_cache_.clear();
  capabilities_.clear();

  ebpf_.SetDeep(true);
  ebpf_.WriteSampleRateCfg(cfg.sample.offcpu_sample_rate, cfg.sample.iofile_sample_rate,
                           cfg.devices.net_event_sample_rate);

  if (!AttachDeepLinks(capabilities_)) {
    ebpf_.SetDeep(false);
    return false;
  }
  if (!OpenProfiler(cfg.sample.profile_freq_hz)) {
    capabilities_.push_back({"oncpu", false, "perf_event_open failed"});
  }

  if (!writer_.OpenDeep(ordinal)) {
    Exit();
    return false;
  }
  active_ = true;

  ResetEpisodeMaps();
  SaveLockHotBaseline();
  gpu_.BeginDeep();

  u32 zero = 0;
  u64 head = 0;
  if (ebpf_.Slice("ring_head")->Lookup(&zero, &head)) prev_head_ = head;

  ExtractPre(anomaly_start_ns, cfg);
  return true;
}

bool DeepCollector::AttachDeepLinks(std::vector<Capability>& caps) {
  // Syscall latency: PRIMARY fentry/fexit on do_syscall_64 (one pair covers
  // every syscall at ~10x lower per-call cost than the raw tracepoint pair);
  // FALLBACK raw_syscalls tp_btf pair on non-x86 / fentry-less kernels.
  {
    const char* prim[] = {"fentry_sys", "fexit_sys"};
    bool prim_ok = true;
    for (const char* n : prim) {
      struct bpf_program* p = ebpf_.Prog(n);
      if (!p) { prim_ok = false; break; }
      struct bpf_link* l = bpf_program__attach(p);
      if (!l) { prim_ok = false; break; }
      deep_links_.push_back(l);
    }
    if (prim_ok) {
      caps.push_back({"fentry_sys", true, ""});
      caps.push_back({"fexit_sys", true, ""});
    } else {
      caps.push_back({"fentry_sys", false, "fallback raw_syscalls tp"});
      caps.push_back({"fexit_sys", false, "fallback raw_syscalls tp"});
      const char* fb[] = {"on_sys_enter", "on_sys_exit"};
      for (const char* n : fb) {
        struct bpf_program* p = ebpf_.Prog(n);
        if (!p) { caps.push_back({n, false, "missing program"}); return false; }
        struct bpf_link* l = bpf_program__attach(p);
        if (!l) { caps.push_back({n, false, strerror(errno)}); return false; }
        deep_links_.push_back(l);
        caps.push_back({n, true, "fallback"});
      }
    }
  }
  // Optional hooks (offcpu/exit). Missing any single one degrades.
  const char* optional[] = {"offcpu_schedule", "on_process_exit"};
  for (const char* n : optional) {
    struct bpf_program* p = ebpf_.Prog(n);
    if (!p) {
      caps.push_back({n, false, "missing program"});
      continue;
    }
    struct bpf_link* l = bpf_program__attach(p);
    if (!l) {
      caps.push_back({n, false, strerror(errno)});
      continue;
    }
    deep_links_.push_back(l);
    caps.push_back({n, true, ""});
  }
  // Off-CPU: if kprobe/__schedule attach failed, enable the stackless
  // on_switch fallback stash so off-CPU dwell still reaches deep_offcpu.
  {
    bool offcpu_ok = false;
    for (const auto& c : caps)
      if (c.name == std::string("offcpu_schedule") && c.available) offcpu_ok = true;
    ebpf_.WriteIntFlag("offcpu_fallback", offcpu_ok ? 0 : 1);
  }

  // File I/O: prefer fentry/fexit; fall back to the kprobe/kretprobe pair on
  // kernels that reject the fentry programs at load (5.15). The fallback keeps
  // the same sampled-entry / measured-exit semantics (empty path + dev/ino).
  {
    const char* primary[] = {"fentry_vfs_read", "fexit_vfs_read",
                             "fentry_vfs_write", "fexit_vfs_write"};
    const char* fallback[] = {"kprobe_vfs_read", "kretprobe_vfs_read",
                              "kprobe_vfs_write", "kretprobe_vfs_write"};
    bool primary_ok = true;
    for (const char* n : primary) {
      struct bpf_program* p = ebpf_.Prog(n);
      if (!p) { primary_ok = false; break; }
      struct bpf_link* l = bpf_program__attach(p);
      if (!l) { primary_ok = false; break; }
      deep_links_.push_back(l);
    }
    if (!primary_ok) {
      // undo any partial primary attach (links stay valid; drop them)
      for (const char* n : primary) caps.push_back({n, false, "5.15 verifier (fallback used)"});
      for (const char* n : fallback) {
        struct bpf_program* p = ebpf_.Prog(n);
        if (!p) { caps.push_back({n, false, "missing program"}); continue; }
        struct bpf_link* l = bpf_program__attach(p);
        if (!l) { caps.push_back({n, false, strerror(errno)}); continue; }
        deep_links_.push_back(l);
        caps.push_back({n, true, "fallback"});
      }
    } else {
      for (const char* n : primary) caps.push_back({n, true, ""});
    }
  }
  // Network hooks — all optional.
  const char* net_optional[] = {
      "net_sock_state",          "net_tcp_retransmit",  "net_kfree_skb",
      "net_tcp_send_reset",      "net_softirq_entry",   "net_softirq_exit",
      "kprobe_tcp_v4_connect",   "kretprobe_tcp_v4_connect",
      "kprobe_tcp_v6_connect",   "kretprobe_tcp_v6_connect",
      "kretprobe_inet_csk_accept", "kprobe_tcp_rcv_established",
  };
  for (const char* n : net_optional) {
    struct bpf_program* p = ebpf_.Prog(n);
    if (!p) {
      caps.push_back({n, false, "missing program"});
      continue;
    }
    struct bpf_link* l = bpf_program__attach(p);
    if (!l) {
      caps.push_back({n, false, strerror(errno)});
      continue;
    }
    deep_links_.push_back(l);
    caps.push_back({n, true, ""});
  }
  return true;
}

void DeepCollector::CloseDeepLinks() {
  for (auto* l : deep_links_) bpf_link__destroy(l);
  deep_links_.clear();
}

bool DeepCollector::OpenProfiler(uint64_t freq_hz) {
  if (freq_hz == 0) return false;
  struct bpf_program* p = ebpf_.Prog("oncpu");
  if (!p) return false;
  int prog_fd = bpf_program__fd(p);

  struct perf_event_attr attr = {};
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.sample_period = 1000000000ULL / freq_hz;  // ~freq_hz samples/sec
  attr.wakeup_events = 1;

  int ncpus = PossibleCpus();
  for (int cpu = 0; cpu < ncpus; ++cpu) {
    int pfd = (int)syscall(__NR_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (pfd < 0) {
      CloseProfiler();
      return false;
    }
    ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
    perf_fds_.push_back(pfd);
  }
  return true;
}

void DeepCollector::CloseProfiler() {
  for (int fd : perf_fds_) close(fd);
  perf_fds_.clear();
}

void DeepCollector::Exit() {
  ebpf_.SetDeep(false);
  CloseProfiler();
  CloseDeepLinks();
  if (active_) writer_.CloseDeep();
  active_ = false;
  targets_.clear();
}

void DeepCollector::ResetEpisodeMaps() {
  const char* maps[] = {"sys_lat",       "sys_st",        "futex_st",
                        "runq_st",       "oncpu_count",   "offcpu_time",
                        "offcpu_stat",   "io_file",       "io_start",
                        "dev_io",        "wakeup_ts",     "offcpu_stash",
                        "offcpu_last_ts", "sock_owner",   "connect_start",
                        "net_flow",      "net_drop",      "net_softirq",
                        "rtt_last"};
  for (const char* n : maps) {
    if (auto* s = ebpf_.Slice(n)) s->Wipe();
  }
  // deep_enabled stays 1; lock_hot is NOT wiped (persistent ranking source) —
  // its per-episode delta comes from the saved baseline.
}

void DeepCollector::SaveLockHotBaseline() {
  lock_hot_base_.clear();
  if (auto* lh = ebpf_.Slice("lock_hot")) {
    lh->ForEach([&](const void* key, const void* value) {
      u64 addr = *(const u64*)key;
      auto* v = (const LockHotVal*)value;
      lock_hot_base_[addr] = v->count;
    });
  }
}

float DeepCollector::PercentileUs(const u32* hist, int bins, u64 base_ns, u64 factor,
                                  double q) const {
  u64 total = 0;
  for (int i = 0; i < bins; ++i) total += hist[i];
  if (total == 0) return 0.0f;
  u64 target = (u64)((double)total * q);
  if (target == 0) target = 1;
  u64 acc = 0;
  for (int i = 0; i < bins; ++i) {
    acc += hist[i];
    if (acc >= target) {
      u64 lo = base_ns;
      for (int k = 0; k < i; ++k) lo *= factor;
      return (float)((double)lo / 1000.0);
    }
  }
  return 0.0f;
}

std::string DeepCollector::Folded(u32 sid, u32 pid, bool user) {
  u64 key = ((u64)sid << 2) | (user ? 2u : 0u);
  auto it = fold_cache_.find(key);
  if (it != fold_cache_.end()) return it->second;

  std::string out;
  auto* sm = ebpf_.Slice("stackmap");
  std::fill(stack_buf_.begin(), stack_buf_.end(), 0);
  if (sm && sm->Lookup(&sid, stack_buf_.data())) {
    int n = 0;
    while (n < 127 && stack_buf_[n] != 0) ++n;
    out = ebpf_.sym().Resolve(pid, stack_buf_.data(), n, user);
  }
  fold_cache_[key] = out;
  return out;
}

void DeepCollector::ExtractPre(uint64_t anomaly_start_ns, const Config& cfg) {
  u64 pre_ns = cfg.window.pre_anomaly_seconds * 1000000000ULL;
  u64 cutoff = anomaly_start_ns > pre_ns ? anomaly_start_ns - pre_ns : 0;

  u32 zero = 0;
  u64 head = 0;
  auto* ring = ebpf_.Slice("ring_head");
  auto* rec = ebpf_.Slice("recorder");
  if (!ring || !rec || !ring->Lookup(&zero, &head)) return;

  u64 cap = bpf_map__max_entries(ebpf_.Map("recorder"));
  u64 start = head > cap ? head - cap : 0;

  std::vector<KernelSnapshotRec> recs;
  recs.reserve(4096);
  for (u64 i = start; i < head; ++i) {
    u32 ix = (u32)(i & (cap - 1));
    KernelSnapshotRec a, b;
    if (!rec->Lookup(&ix, &a)) continue;
    if (a.seq & 1) continue;
    if (!rec->Lookup(&ix, &b)) continue;
    if (a.seq != b.seq || a.seq != (i << 1)) continue;
    if (b.ts_ns >= cutoff) recs.push_back(b);
  }

  if (EbpfManager::RecorderPerCpu())
    recs = MergePerCpu(std::move(recs), pre_interval_ms_);
  else
    std::sort(recs.begin(), recs.end(),
              [](const auto& a, const auto& b) { return a.ts_ns < b.ts_ns; });

  writer_.BeginBatch();
  for (const auto& r : recs) {
    CanonicalSnapshot s;
    DecodeSnapshot(r, s);
    writer_.WritePreSeries(s);
  }
  writer_.CommitBatch();
  LogInfo("deep pre-window extracted: %zu records (head=%llu)", recs.size(),
          (unsigned long long)head);
}

void DeepCollector::DrainPost() {
  u32 zero = 0;
  u64 head = 0;
  auto* ring = ebpf_.Slice("ring_head");
  auto* rec = ebpf_.Slice("recorder");
  if (!ring || !rec || !ring->Lookup(&zero, &head)) return;

  u64 cap = bpf_map__max_entries(ebpf_.Map("recorder"));
  u64 begin = prev_head_ + 1;

  writer_.BeginBatch();
  if (head - prev_head_ >= cap - 64) {
    writer_.WritePostSeriesGap(prev_head_, head);
    LogWarn("flight recorder overrun: gap [%llu, %llu)", (unsigned long long)prev_head_,
            (unsigned long long)head);
  }

  std::vector<KernelSnapshotRec> recs;
  for (u64 i = begin; i <= head; ++i) {
    u32 ix = (u32)(i & (cap - 1));
    KernelSnapshotRec a, b;
    if (!rec->Lookup(&ix, &a)) continue;
    if (a.seq & 1) continue;
    if (!rec->Lookup(&ix, &b)) continue;
    if (a.seq != b.seq || a.seq != (i << 1)) continue;
    recs.push_back(b);
  }
  prev_head_ = head;

  if (EbpfManager::RecorderPerCpu())
    recs = MergePerCpu(std::move(recs), post_interval_ms_);
  else
    std::sort(recs.begin(), recs.end(),
              [](const auto& a, const auto& b) { return a.ts_ns < b.ts_ns; });

  for (const auto& r : recs) {
    CanonicalSnapshot s;
    DecodeSnapshot(r, s);
    writer_.WritePostSeries(s);
  }
  writer_.CommitBatch();
}

void DeepCollector::DrainProcesses(uint64_t now_ns) {
  // All fields come from the single iter/task eBPF pass stored in
  // process_table_; no per-thread /proc reads in DEEP.
  std::unordered_map<u32, const ProcessRow*> by_tid;
  by_tid.reserve(process_table_.size());
  for (const auto& r : process_table_) by_tid[r.pid] = &r;

  writer_.BeginBatch();
  for (uint32_t tid : targets_) {
    DeepProcessRow r;
    r.ordinal = ordinal_;
    r.ts_ns = now_ns;
    r.tid = tid;
    auto it = by_tid.find(tid);
    if (it == by_tid.end()) {
      r.tgid = tid;
      r.available = false;
      r.error = "tid not in process table";
      writer_.WriteDeepProcess(r);
      continue;
    }
    const ProcessRow* p = it->second;
    r.tgid = p->tgid ? p->tgid : tid;
    r.comm = p->comm;
    r.available = true;
    if (p->rss_valid) {
      r.vm_rss_kb = p->rss_kb;
      r.rss_anon_kb = p->rss_anon_pages * 4;
      r.rss_file_kb = p->rss_file_pages * 4;
      r.rss_shmem_kb = p->rss_shmem_pages * 4;
      r.vm_swap_kb = p->swap_ents * 4;
      r.status_valid = true;
    }
    if (p->ioac_valid) {
      r.rchar = p->rchar;
      r.wchar = p->wchar;
      r.read_bytes = p->read_bytes;
      r.write_bytes = p->write_bytes;
      r.syscr = p->syscr;
      r.syscw = p->syscw;
      r.io_valid = true;
    }
    if (p->sched_valid) {
      r.sched_exec_runtime_ns = p->sum_exec_runtime_ns;
      r.sched_run_delay_ns = p->run_delay_ns;
      r.sched_switch_count = p->nvcsw + p->nivcsw;
      r.sched_valid = true;
    }
    writer_.WriteDeepProcess(r);
  }
  writer_.CommitBatch();
}

void DeepCollector::DrainGpu(uint64_t now_ns) {
  if (targets_.empty()) return;
  std::unordered_set<uint32_t> tgids;
  std::unordered_map<u32, uint32_t> tid2tgid;
  for (const auto& r : process_table_) tid2tgid[r.pid] = r.tgid ? r.tgid : r.pid;
  for (uint32_t tid : targets_) {
    auto it = tid2tgid.find(tid);
    uint32_t tgid = (it != tid2tgid.end() && it->second) ? it->second : tid;
    tgids.insert(tgid);
  }
  auto rows = gpu_.SnapshotProcesses(tgids, now_ns);
  if (rows.empty()) return;
  writer_.BeginBatch();
  for (auto& r : rows) {
    r.ordinal = ordinal_;
    writer_.WriteDeepGpuProcess(r);
  }
  writer_.CommitBatch();
}

void DeepCollector::DumpDeepMaps(const Config& /*cfg*/) {
  writer_.BeginBatch();

  // Attribution tables from task_meta: tid -> tgid, tid -> comm.
  std::unordered_map<u32, u32> tid_tgid;
  std::unordered_map<u32, std::string> tid_comm;
  if (auto* tm = ebpf_.Slice("task_meta")) {
    tm->ForEach([&](const void* key, const void* val) {
      u32 tid = *(const u32*)key;
      auto* v = (const TaskMetaVal*)val;
      tid_tgid[tid] = v->tgid;
      tid_comm[tid] = SanitizeCommStr((const char*)v->comm, 16);
    });
  }

  // syscall latency table (+ error_count)
  auto* syslat = ebpf_.Slice("sys_lat");
  syslat->ForEach([&](const void* key, const void* value) {
    auto* k = (const SysLatKey*)key;
    auto* v = (const SysLatVal*)value;
    float p50 = PercentileUs(v->hist, kHist64Bins, 1, 2, 0.50);
    float p99 = PercentileUs(v->hist, kHist64Bins, 1, 2, 0.99);
    writer_.WriteDeepSyscall(k->tid, k->id, v->count,
                             v->count ? (float)((double)v->lat_sum / v->count / 1000.0) : 0.0f,
                             p50, p99, v->error_count);
  });

  // on-CPU folded profile
  auto* oncp = ebpf_.Slice("oncpu_count");
  oncp->ForEach([&](const void* key, const void* value) {
    auto* k = (const OncpuKey*)key;
    u64 count = *(const u64*)value;
    std::string us = Folded(k->user_sid, k->pid, true);
    std::string ks = Folded(k->kernel_sid, k->pid, false);
    std::string pc, tc;
    if (auto it = tid_comm.find(k->tid); it != tid_comm.end()) tc = it->second;
    if (auto it = tid_comm.find(k->pid); it != tid_comm.end()) pc = it->second;
    std::string line = "p:" + std::to_string(k->pid) + "/" + pc + ";t:" +
                       std::to_string(k->tid) + "/" + tc;
    if (!ks.empty()) line += ";" + ks;   // kernel frames (root-first) near root
    if (!us.empty()) line += ";" + us;   // user frames (root-first) at leaf side
    writer_.WriteFoldedLine("on_cpu", line, count);
  });

  // off-CPU folded (stack_available samples; ksid==0 still emitted)
  auto* offcp = ebpf_.Slice("offcpu_time");
  offcp->ForEach([&](const void* key, const void* value) {
    const u32* k = (const u32*)key;  // { tid, ksid }
    u64 dwell = *(const u64*)value;
    std::string ks = Folded(k[1], k[0], false);
    std::string line;
    if (auto tg = tid_tgid.find(k[0]); tg != tid_tgid.end()) {
      const std::string& c = tid_comm[k[0]];
      line = "p:" + std::to_string(tg->second) + "/" + c + ";t:" + std::to_string(k[0]) +
             "/" + c;
    } else {
      line = "t:" + std::to_string(k[0]) + "/";
    }
    writer_.WriteFoldedLine("off_cpu", line + ";" + ks, dwell);
  });

  // stackless off-CPU per-tid aggregation -> deep_offcpu
  auto* offstat = ebpf_.Slice("offcpu_stat");
  offstat->ForEach([&](const void* key, const void* value) {
    u32 tid = *(const u32*)key;
    auto* v = (const LatStatVal13*)value;
    DeepOffcpuRow r;
    r.ordinal = ordinal_;
    r.tid = tid;
    r.tgid = tid_tgid.count(tid) ? tid_tgid[tid] : 0;
    r.comm = tid_comm.count(tid) ? tid_comm[tid] : "";
    r.dwell_ns = v->lat_sum;
    r.count = v->count;
    r.stack_available = 0;
    writer_.WriteDeepOffcpu(r);
  });

  // lock hot spots — episode delta against the saved baseline.
  auto* lockhot = ebpf_.Slice("lock_hot");
  lockhot->ForEach([&](const void* key, const void* value) {
    u64 addr = *(const u64*)key;
    auto* v = (const LockHotVal*)value;
    u64 base = lock_hot_base_.count(addr) ? lock_hot_base_[addr] : 0;
    u64 cnt = v->count > base ? v->count - base : 0;
    if (cnt == 0) return;
    std::string sym = ebpf_.sym().KernelSym(addr);
    writer_.WriteDeepLock(addr, cnt, v->lat_sum, sym.c_str());
  });

  // per-file I/O with actual bytes/errors/latency histogram
  auto* iofile = ebpf_.Slice("io_file");
  iofile->ForEach([&](const void* key, const void* value) {
    auto* k = (const IoFileKey*)key;
    auto* v = (const IoFileVal*)value;
    float p50 = PercentileUs(v->hist, kHist13Bins, 256, 4, 0.50);
    float p99 = PercentileUs(v->hist, kHist13Bins, 256, 4, 0.99);
    writer_.WriteDeepIoFile(k->dev, k->ino, k->path, v->bytes, v->ops, v->errors, v->lat_sum,
                            v->hist, p50, p99);
  });

  // per-device block I/O -> deep_io_device (DEEP-only dev_io dump)
  auto* devio = ebpf_.Slice("dev_io");
  devio->ForEach([&](const void* key, const void* value) {
    u32 dev = *(const u32*)key;
    auto* v = (const BlockIoVal*)value;
    DeepIoDeviceRow r;
    r.ordinal = ordinal_;
    r.dev = dev;
    r.ops = v->ops;
    r.bytes = v->bytes;
    r.lat_sum = v->lat_sum;
    for (int i = 0; i < kHist13Bins; ++i) r.hist[i] = v->hist[i];
    r.p50_us = PercentileUs(v->hist, kHist13Bins, 256, 4, 0.50);
    r.p99_us = PercentileUs(v->hist, kHist13Bins, 256, 4, 0.99);
    writer_.WriteDeepIoDevice(r);
  });

  // network flows: closed set (net_flow) + live owner set (sock_owner)
  auto write_flow = [&](u64 cookie, const SockOwnerVal* v, bool closed) {
    DeepNetFlowRow r;
    r.ordinal = ordinal_;
    r.cookie = cookie;
    r.tgid = (uint32_t)v->tgid;
    r.tid = v->tid;
    r.netns_ino = v->netns_ino;
    r.family = v->family;
    r.local_addr = v->local_addr[0] | ((u64)v->local_addr[1] << 32);
    r.local_port = v->local_port;
    r.remote_addr = v->remote_addr[0] | ((u64)v->remote_addr[1] << 32);
    r.remote_port = v->remote_port;
    r.start_ts_ns = v->start_ts;
    r.established_ts_ns = v->established_ts;
    r.end_ts_ns = 0;
    r.duration_us = 0;
    r.connect_latency_us =
        (v->established_ts > v->start_ts) ? (v->established_ts - v->start_ts) / 1000 : 0;
    r.tx_bytes = v->tx_bytes;
    r.rx_bytes = v->rx_bytes;
    r.retransmits = v->retrans;
    r.rst_reason = v->rst_reason;
    r.rtt_count = v->rtt_count;
    r.rtt_avg_us = v->rtt_count ? v->rtt_sum_us / v->rtt_count : 0;
    r.closed = closed;
    r.owner_available = v->tid != 0;
    writer_.WriteDeepNetFlow(r);
  };
  auto* flow = ebpf_.Slice("net_flow");
  flow->ForEach([&](const void* key, const void* value) {
    write_flow(*(const u64*)key, (const SockOwnerVal*)value, true);
  });
  auto* owner = ebpf_.Slice("sock_owner");
  owner->ForEach([&](const void* key, const void* value) {
    write_flow(*(const u64*)key, (const SockOwnerVal*)value, false);
  });

  // drops
  auto* drops = ebpf_.Slice("net_drop");
  drops->ForEach([&](const void* key, const void* value) {
    auto* k = (const NetDropKeyVal*)key;
    u64 count = *(const u64*)value;
    DeepNetDropRow r;
    r.ordinal = ordinal_;
    r.netns_ino = k->netns_ino;
    r.ifindex = k->ifindex;
    r.reason_id = k->reason_id;
    r.count = count;
    writer_.WriteDeepNetDrop(r);
  });

  // softirqs
  auto* soft = ebpf_.Slice("net_softirq");
  soft->ForEach([&](const void* key, const void* value) {
    auto* k = (const NetSoftirqKeyVal*)key;
    auto* v = (const LatStatVal13*)value;
    DeepNetSoftirqRow r;
    r.ordinal = ordinal_;
    r.cpu_idx = k->cpu_idx;
    r.vector = k->vector;
    r.vector_name = k->vector == 3 ? "NET_RX" : (k->vector == 2 ? "NET_TX" : "other");
    r.count = v->count;
    r.time_ns = v->lat_sum;
    std::string h = "[";
    for (int i = 0; i < kHist13Bins; ++i) {
      if (i) h += ",";
      h += std::to_string(v->hist[i]);
    }
    h += "]";
    r.hist = h;
    writer_.WriteDeepNetSoftirq(r);
  });

  writer_.CommitBatch();
}

void DeepCollector::Tick(uint64_t now_ns, const Config& cfg) {
  if (!active_) return;
  // Ring drain runs every main loop: the per-CPU sampler on wide machines
  // produces far more records than deep_dump_interval can absorb; the ring
  // must never wait for the process/GPU cadence.
  DrainPost();
  if (now_ns >= next_dump_ns_) {
    DrainProcesses(now_ns);
    next_dump_ns_ = now_ns + cfg.sample.deep_dump_interval_ms * 1000000ULL;
  }
  if (cfg.devices.deep_gpu_enabled && now_ns >= next_gpu_ns_) {
    DrainGpu(now_ns);
    next_gpu_ns_ = now_ns + cfg.devices.deep_gpu_interval_ms * 1000000ULL;
  }
}

void DeepCollector::Finalize(const Config& cfg, nlohmann::json& summary_json) {
  uint64_t now = NowNs();
  DrainPost();
  DrainProcesses(now);
  if (cfg.devices.deep_gpu_enabled) DrainGpu(now);
  DumpDeepMaps(cfg);
  summary_json["post_series_records"] = prev_head_;

  nlohmann::json caps = nlohmann::json::array();
  for (const auto& c : capabilities_)
    caps.push_back({{"name", c.name}, {"available", c.available}, {"error", c.error}});
  summary_json["capabilities"] = caps;
}

}  // namespace etrace_diag
