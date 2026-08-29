#include "collect/deep_collector.h"

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>
#include <utility>

#include "logging.h"

namespace etrace_diag {

namespace {

// Mirrors of DEEP result map keys/values (frozen layout; matches etrace.bpf.c).
struct OncpuKey { u32 pid; u32 user_sid; u32 kernel_sid; };
struct OffcpuKey { u32 tid; u32 ksid; };
struct SysLatKey { u32 tid; u32 id; };
struct SysLatVal { u64 count; u64 lat_sum; u32 hist[64]; };
struct IoFileKey { u32 dev; u64 ino; char path[256]; };
struct IoFileVal { u64 bytes; u32 ops; };
struct LockHotVal { u64 count; u64 lat_sum; };
struct LatStatVal13 { u64 count; u64 lat_sum; u32 hist[13]; };

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
std::vector<KernelSnapshotRec> MergePerCpu(std::vector<KernelSnapshotRec> in, uint64_t interval_ms) {
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
}  // namespace


DeepCollector::DeepCollector(EbpfManager& ebpf, OutputWriter& writer)
    : ebpf_(ebpf), writer_(writer) {
  stack_buf_.resize(127);
}

bool DeepCollector::Enter(int ordinal, uint64_t anomaly_start_ns, const Config& cfg) {
  ordinal_ = ordinal;
  anomaly_start_ns_ = anomaly_start_ns;
  pre_interval_ms_ = cfg.sample.fine_interval_ms;
  post_interval_ms_ = cfg.sample.deep_fine_interval_ms;
  ebpf_.SetDeep(true);
  ebpf_.WriteSampleRateCfg(cfg.sample.offcpu_sample_rate, cfg.sample.iofile_sample_rate);

  if (!AttachDeepLinks()) {
    ebpf_.SetDeep(false);
    return false;
  }
  if (!OpenProfiler(cfg.sample.profile_freq_hz)) {
    LogWarn("on-CPU profiler could not be opened (continuing without on-cpu profile)");
  }

  if (!writer_.OpenDeep(ordinal)) {
    Exit();
    return false;
  }
  active_ = true;

  u32 zero = 0;
  u64 head = 0;
  if (ebpf_.Slice("ring_head")->Lookup(&zero, &head)) prev_head_ = head;

  ExtractPre(anomaly_start_ns, cfg);
  return true;
}

void DeepCollector::Tick() {
  if (!active_) return;
  DrainPost();
}

bool DeepCollector::AttachDeepLinks() {
  const char* names[] = {"on_sys_enter", "on_sys_exit", "do_vfs_read",
                         "do_vfs_write", "file_open_path"};
  for (const char* n : names) {
    struct bpf_program* p = ebpf_.Prog(n);
    if (!p) return false;
    struct bpf_link* l = bpf_program__attach(p);
    if (!l) {
      LogError("deep attach %s: %s", n, strerror(errno));
      return false;
    }
    deep_links_.push_back(l);
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
  auto it = fold_cache_.find(sid);
  if (it != fold_cache_.end()) return it->second;

  std::string out;
  auto* sm = ebpf_.Slice("stackmap");
  std::fill(stack_buf_.begin(), stack_buf_.end(), 0);
  if (sm && sm->Lookup(&sid, stack_buf_.data())) {
    int n = 0;
    while (n < 127 && stack_buf_[n] != 0) ++n;
    out = ebpf_.sym().Resolve(pid, stack_buf_.data(), n, user);
  }
  fold_cache_[sid] = out;
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

  for (const auto& r : recs) {
    CanonicalSnapshot s;
    DecodeSnapshot(r, s);
    writer_.WritePreSeries(s);
  }
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
}

void DeepCollector::DumpDeepMaps(const Config& /*cfg*/) {
  std::ostringstream syscall, lock, runq, iof;
  std::string folded_on_cpu, folded_off_cpu;

  auto* syslat = ebpf_.Slice("sys_lat");
  syslat->ForEach([&](const void* key, const void* value) {
    auto* k = (const SysLatKey*)key;
    auto* v = (const SysLatVal*)value;
    float p50 = PercentileUs(v->hist, 64, 1, 2, 0.50);
    float p99 = PercentileUs(v->hist, 64, 1, 2, 0.99);
    syscall << "tid=" << k->tid << " syscall=" << k->id << " count=" << v->count
            << " avg_us=" << (v->count ? (double)v->lat_sum / v->count / 1000.0 : 0)
            << " p50_us=" << p50 << " p99_us=" << p99 << "\n";
  });
  writer_.WriteText("syscall_hotspot.txt", syscall.str());

  auto* oncp = ebpf_.Slice("oncpu_count");
  oncp->ForEach([&](const void* key, const void* value) {
    auto* k = (const OncpuKey*)key;
    u64 count = *(const u64*)value;
    std::string us = Folded(k->user_sid, k->pid, true);
    std::string ks = Folded(k->kernel_sid, k->pid, false);
    std::string line = ks.empty() ? us : (us.empty() ? ks : us + ";" + ks);
    if (!line.empty()) folded_on_cpu += line + " " + std::to_string(count) + "\n";
  });
  writer_.WriteFolded("on_cpu.folded", folded_on_cpu);

  auto* offcp = ebpf_.Slice("offcpu_time");
  offcp->ForEach([&](const void* key, const void* value) {
    auto* k = (const OffcpuKey*)key;
    u64 dwell = *(const u64*)value;
    std::string ks = Folded(k->ksid, k->tid, false);
    if (!ks.empty()) folded_off_cpu += ks + " " + std::to_string(dwell) + "\n";
  });
  writer_.WriteFolded("off_cpu.folded", folded_off_cpu);

  auto* lockhot = ebpf_.Slice("lock_hot");
  lockhot->ForEach([&](const void* key, const void* value) {
    u64 addr = *(const u64*)key;
    auto* v = (const LockHotVal*)value;
    lock << "0x" << std::hex << addr << std::dec << " count=" << v->count
         << " total_wait_ns=" << v->lat_sum
         << " avg_wait_ns=" << (v->count ? v->lat_sum / v->count : 0) << "\n";
  });
  writer_.WriteText("lock_contention.txt", lock.str());

  auto* runq_slice = ebpf_.Slice("runq_st");
  runq_slice->ForEach([&](const void* key, const void* value) {
    u32 tid = *(const u32*)key;
    auto* v = (const LatStatVal13*)value;
    float p50 = PercentileUs(v->hist, 13, 256, 4, 0.50);
    float p99 = PercentileUs(v->hist, 13, 256, 4, 0.99);
    runq << "tid=" << tid << " count=" << v->count
         << " avg_us=" << (v->count ? (double)v->lat_sum / v->count / 1000.0 : 0)
         << " p50_us=" << p50 << " p99_us=" << p99 << "\n";
  });
  writer_.WriteText("runq_latency.txt", runq.str());

  auto* iofile = ebpf_.Slice("io_file");
  iofile->ForEach([&](const void* key, const void* value) {
    auto* k = (const IoFileKey*)key;
    auto* v = (const IoFileVal*)value;
    iof << "dev=0x" << std::hex << k->dev << std::dec << " ino=" << k->ino
        << " path=" << k->path << " bytes=" << v->bytes << " ops=" << v->ops << "\n";
  });
  writer_.WriteText("io_files.txt", iof.str());
}

void DeepCollector::Finalize(const Config& cfg, nlohmann::json& summary_json) {
  DrainPost();
  DumpDeepMaps(cfg);
  summary_json["post_series_records"] = prev_head_;
}

}  // namespace etrace_diag