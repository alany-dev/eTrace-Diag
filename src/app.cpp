#include "etrace_diag/app.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <sys/resource.h>
#include <fstream>
#include <memory>
#include <thread>
#include <unordered_set>

#include "collect/deep_collector.h"
#include "collect/ebpf_manager.h"
#include "collect/host_metrics.h"
#include "collect/target_selector.h"
#include "etrace_diag/model_client.h"
#include "etrace_diag/output_writer.h"
#include "logging.h"
#include "model/features.h"
#include "phase_manager.h"

namespace etrace_diag {

namespace {

uint64_t NowNs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Reads /proc/self/status VmRSS/VmHWM (kB), leaving 0 on failure.
void SelfVm(uint64_t& rss_kb, uint64_t& hwm_kb) {
  rss_kb = hwm_kb = 0;
  std::ifstream f("/proc/self/status");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("VmRSS:", 0) == 0)
      rss_kb = strtoull(line.c_str() + 6, nullptr, 10);
    else if (line.rfind("VmHWM:", 0) == 0)
      hwm_kb = strtoull(line.c_str() + 6, nullptr, 10);
  }
}

// Cumulative self overhead: CPU time / ctx switches / faults are cumulative
// (deltas computed downstream, matching the canonical-snapshot convention);
// RSS/HWM are instantaneous.
ProcOverhead BuildProcOverhead(uint64_t ts_ns) {
  ProcOverhead o;
  o.ts_ns = ts_ns;
  struct rusage ru;
  if (getrusage(RUSAGE_SELF, &ru) == 0) {
    o.utime_ns = (uint64_t)ru.ru_utime.tv_sec * 1000000000ULL + ru.ru_utime.tv_usec * 1000ULL;
    o.stime_ns = (uint64_t)ru.ru_stime.tv_sec * 1000000000ULL + ru.ru_stime.tv_usec * 1000ULL;
    o.nvcsw = (uint64_t)ru.ru_nvcsw;
    o.nivcsw = (uint64_t)ru.ru_nivcsw;
    o.minflt = (uint64_t)ru.ru_minflt;
    o.majflt = (uint64_t)ru.ru_majflt;
  }
  SelfVm(o.rss_kb, o.vmhwm_kb);
  return o;
}

// Best-effort write of kernel.bpf_stats_enabled=1; stores the previous value
// in `prev` for restoration. Returns false if the sysctl is not writable.
bool EnableBpfStats(std::string& prev) {
  const char* path = "/proc/sys/kernel/bpf_stats_enabled";
  std::ifstream in(path);
  prev.clear();
  if (in.good()) {
    std::getline(in, prev);
    while (!prev.empty() && (prev.back() == '\n' || prev.back() == '\r')) prev.pop_back();
  }
  std::ofstream out(path);
  if (!out.good()) { prev.clear(); return false; }
  out << "1\n";
  if (!out.good()) { prev.clear(); return false; }
  return true;
}

void RestoreBpfStats(const std::string& prev) {
  if (prev.empty()) return;
  std::ofstream out("/proc/sys/kernel/bpf_stats_enabled");
  if (out.good()) out << prev << "\n";
}

// Mirrors of kernel per-tid counter values.
struct SwitchVal { u32 vol; u32 invol; };
struct BlockIoVal { u64 ops; u64 bytes; u64 lat_sum; u32 hist[13]; };
struct FaultsVal { u32 minor; u32 major; };
struct LatStatVal13 { u64 count; u64 lat_sum; u32 hist[13]; };
struct MemEventsVal { u32 kswapd_active; u32 direct_reclaim; u64 nr_reclaimed; };
struct OomEventVal { u64 ts; u32 pid; };

EbpfCounters BuildEbpfCounters(EbpfManager& ebpf, uint64_t ts_ns,
                               const std::unordered_set<uint32_t>& members) {
  EbpfCounters c;
  c.ts_ns = ts_ns;

  auto sum_block = [&](u32 tid, u64& ops, u64& bytes) {
    BlockIoVal bi = {};
    if (ebpf.Slice("block_io")->LookupPercpuSum(&tid, &bi)) {
      ops = bi.ops;
      bytes = bi.bytes;
    }
  };
  auto sum_faults = [&](u32 tid, u64& minor, u64& major) {
    FaultsVal ft = {};
    if (ebpf.Slice("faults")->LookupPercpuSum(&tid, &ft)) {
      minor = ft.minor;
      major = ft.major;
    }
  };
  auto sum_lock = [&](u32 tid, u64& waits) {
    LatStatVal13 lk = {};
    if (ebpf.Slice("lock_st")->LookupPercpuSum(&tid, &lk)) waits = lk.count;
  };

  ebpf.Slice("on_cpu_ns")->ForEach([&](const void* key, const void* value) {
    u32 tid = *(const u32*)key;
    u64 on_cpu = *(const u64*)value;
    EbpfPerTidStats t;
    t.tid = tid;
    t.on_cpu_ns = on_cpu;
    SwitchVal sw = {};
    if (ebpf.Slice("switches")->LookupPercpuSum(&tid, &sw)) {
      t.nr_sw_vol = sw.vol;
      t.nr_sw_invol = sw.invol;
    }
    sum_block(tid, t.io_ops, t.io_bytes);
    sum_faults(tid, t.pf_minor, t.pf_major);
    sum_lock(tid, t.lock_waits);

    c.on_cpu_ns_total += on_cpu;
    c.switch_total += t.nr_sw_vol + t.nr_sw_invol;
    c.io_ops_total += t.io_ops;
    c.io_bytes_total += t.io_bytes;
    c.faults_total += t.pf_minor + t.pf_major;
    c.lock_waits_total += t.lock_waits;
    if (members.count(tid)) c.per_tid.push_back(t);
  });
  std::sort(c.per_tid.begin(), c.per_tid.end(),
            [](const auto& a, const auto& b) { return a.on_cpu_ns > b.on_cpu_ns; });
  return c;
}

void DumpMemEvents(EbpfManager& ebpf, OutputWriter& writer, uint64_t ts_ns) {
  static MemEventsVal last = {};
  u32 zero = 0;
  MemEventsVal m = {};
  ebpf.Slice("mem_events")->Lookup(&zero, &m);
  if (m.kswapd_active == last.kswapd_active && m.direct_reclaim == last.direct_reclaim &&
      m.nr_reclaimed == last.nr_reclaimed)
    return;
  last = m;
  nlohmann::json e = {{"v", 1}, {"ts_ns", ts_ns}, {"kswapd_active", m.kswapd_active},
                      {"direct_reclaim", m.direct_reclaim}, {"nr_reclaimed", m.nr_reclaimed}};
  writer.WriteMemoryEvent(e);
}

void DumpOomEvents(EbpfManager& ebpf, OutputWriter& writer) {
  static u32 last_seq = 0;
  u32 zero = 0;
  u32 seq = 0;
  if (!ebpf.Slice("oom_seq")->Lookup(&zero, &seq)) return;
  if (seq == last_seq) return;

  u32 begin = last_seq;
  for (u32 s = begin; s < seq && s - begin < 1000; ++s) {
    u32 ix = s & 63;
    OomEventVal ev = {};
    if (!ebpf.Slice("oom_events")->Lookup(&ix, &ev)) continue;
    std::string comm = HostMetrics::ReadComm(ev.pid);
    nlohmann::json e = {{"v", 1}, {"ts_ns", ev.ts}, {"pid", ev.pid}, {"comm", comm}};
    writer.WriteMemoryEvent(e);
  }
  last_seq = seq;
}

void DumpIoDevices(EbpfManager& ebpf, OutputWriter& writer, uint64_t ts_ns) {
  ebpf.Slice("dev_io")->ForEach([&](const void* key, const void* value) {
    u32 dev = *(const u32*)key;
    const auto* bi = (const BlockIoVal*)value;
    nlohmann::json hist = nlohmann::json::array();
    for (int i = 0; i < 13; ++i) hist.push_back(bi->hist[i]);
    nlohmann::json e = {{"v", 1}, {"ts_ns", ts_ns}, {"dev", dev}, {"ops", bi->ops},
                        {"bytes", bi->bytes}, {"lat_sum", bi->lat_sum}, {"hist", hist}};
    writer.WriteIoDevice(e);
  });
}

// One aggregated ProcessRow per selected process (the canonical top-K process
// table), summed from the host process table's per-thread rows.
std::vector<ProcessRow> BuildTopTasks(const HostSnapshot& host,
                                      const std::unordered_set<uint32_t>& procs) {
  std::unordered_map<uint32_t, ProcessRow> agg;
  for (const auto& r : host.procs) {
    uint32_t g = r.tgid ? r.tgid : r.pid;
    if (!procs.count(g)) continue;
    ProcessRow& a = agg[g];
    if (!a.tgid) {
      a.tgid = g;
      a.pid = g;
      a.state = r.state;
      a.start_time = r.start_time;
    }
    if (r.pid == g) {  // main thread: keep its comm
      std::memcpy(a.comm, r.comm, 15);
      a.comm[15] = 0;
    }
    a.utime += r.utime;
    a.stime += r.stime;
    a.nvcsw += r.nvcsw;
    a.nivcsw += r.nivcsw;
    a.total_vm += r.total_vm;
  }
  std::vector<ProcessRow> out;
  out.reserve(agg.size());
  for (auto& [g, a] : agg) {
    a.rss_kb = HostMetrics::ReadVmRss(g);
    out.push_back(a);
  }
  std::sort(out.begin(), out.end(), [](const ProcessRow& a, const ProcessRow& b) {
    return (a.utime + a.stime) > (b.utime + b.stime);
  });
  return out;
}

AnomalyFeatures BuildFeatures(const Config& cfg, uint64_t seq, const HostSnapshot& host,
                              EbpfManager& ebpf, const std::unordered_set<uint32_t>& members,
                              const std::unordered_set<uint32_t>& procs) {
  AnomalyFeatures f;
  f.seq = seq;
  f.ts_ns = host.ts_ns;
  f.host = host;

  // Focus filter (debug/benchmark): restrict host procs to one pid.
  if (cfg.misc.pid_filter) {
    f.host.procs.erase(
        std::remove_if(f.host.procs.begin(), f.host.procs.end(), [&](const ProcessRow& p) {
          return (p.tgid ? p.tgid : p.pid) != cfg.misc.pid_filter;
        }),
        f.host.procs.end());
  }

  f.ebpf = BuildEbpfCounters(ebpf, host.ts_ns, members);

  std::unordered_set<uint32_t> want = procs;
  if (cfg.misc.pid_filter) {
    want.clear();
    want.insert((uint32_t)cfg.misc.pid_filter);
  }
  f.top_tasks = BuildTopTasks(host, want);
  return f;
}

std::shared_ptr<const Config> ReloadConfig(const Config& base, const std::string& path) {
  Config c = base;
  if (!path.empty()) {
    std::ifstream f(path);
    if (f.good()) {
      nlohmann::json j;
      try {
        f >> j;
        c = MergeConfig(c, j);
      } catch (const std::exception& e) {
        LogWarn("config reload: %s", e.what());
      }
    }
  }
  ApplyEnvOverrides(c);
  Sanitize(c);
  return std::make_shared<const Config>(c);
}

}  // namespace

int RunCollector(const Config& initial, const std::string& config_path, uint64_t run_seconds,
                 SignalState& sig) {
  std::shared_ptr<const Config> cfg = std::make_shared<const Config>(initial);

  OutputWriter writer;
  if (!writer.Init(initial)) {
    LogError("cannot initialize output directory '%s'", initial.output.dir.c_str());
    return 1;
  }
  Logger::Instance().Init(writer.session_dir() + "/log.txt",
                          ParseLogLevel(initial.misc.log_level));
  LogInfo("session dir: %s", writer.session_dir().c_str());

  std::string bpf_stats_prev;
  bool bpf_stats_ok = false;
  if (cfg->misc.enable_bpf_stats) {
    bpf_stats_ok = EnableBpfStats(bpf_stats_prev);
    LogInfo("kernel.bpf_stats_enabled=%s (previous=%s)", bpf_stats_ok ? "1" : "unavailable",
            bpf_stats_prev.empty() ? "unknown" : bpf_stats_prev.c_str());
  }

  EbpfManager ebpf;
  if (!ebpf.Load()) {
    LogError("BPF load failed (kernel >= 6.6 with CONFIG_DEBUG_INFO_BTF required)");
    return 1;
  }

  // Push sampling config into the kernel + start the flight recorder.
  ebpf.WriteNcpus(PossibleCpus());
  ebpf.WriteSampleRateCfg(cfg->sample.offcpu_sample_rate, cfg->sample.iofile_sample_rate);
  if (!ebpf.StartSnapshotter(cfg->sample.fine_interval_ms)) {
    LogError("failed to start the flight-recorder snapshotter");
    return 1;
  }

  TargetSelector selector(ebpf, writer);
  selector.ApplyPinned(*cfg);
  selector.Probe(*cfg);

  auto model = MakeModelClient(*cfg);
  DeepCollector deep(ebpf, writer);
  PhaseManager phase(writer, deep, std::move(model));

  uint64_t t0 = NowNs();
  uint64_t next_host = 0, next_feature = 0, next_topk = 0, next_deep = 0;
  uint64_t seq = 0;
  uint64_t next_overhead = 0;
  uint64_t last_overhead_ts = 0;
  uint64_t cur_interval_ms = cfg->sample.fine_interval_ms;
  HostSnapshot last_host;

  while (!sig.stop.load()) {
    if (run_seconds &&
        NowNs() - t0 >= run_seconds * 1000000000ULL)
      break;

    if (sig.reload.exchange(false)) {
      cfg = ReloadConfig(initial, config_path);
      ebpf.WriteSampleRateCfg(cfg->sample.offcpu_sample_rate, cfg->sample.iofile_sample_rate);
      selector.Probe(*cfg);
      LogInfo("config reloaded (fine_interval_ms=%llu)",
              (unsigned long long)cfg->sample.fine_interval_ms);
    }

    uint64_t now = NowNs();

    if (now >= next_host) {
      last_host = HostMetrics::Snapshot();
      // Process table from iter/task, capped to the top-CPU tasks (the full
      // table is huge at 1s resolution and adds no signal).
      std::vector<ProcessRow> procs;
      if (ebpf.ReadProcessTable(procs)) {
        std::sort(procs.begin(), procs.end(), [](const ProcessRow& a, const ProcessRow& b) {
          return (a.utime + a.stime) > (b.utime + b.stime);
        });
        if (procs.size() > 200) procs.resize(200);
        last_host.procs = std::move(procs);
      }
      writer.WriteHostRow(last_host);
      DumpMemEvents(ebpf, writer, last_host.ts_ns);
      DumpOomEvents(ebpf, writer);
      DumpIoDevices(ebpf, writer, last_host.ts_ns);
      next_host = now + cfg->sample.base_host_interval_ms * 1000000ULL;
    }

    if (now >= next_overhead) {
      ProcOverhead po = BuildProcOverhead(now);
      writer.WriteProcOverhead(po);
      if (bpf_stats_ok) {
        BpfStatsSnapshot bs;
        bs.ts_ns = now;
        bs.interval_ns = last_overhead_ts ? now - last_overhead_ts : 0;
        bs.stats_enabled = true;
        ebpf.CollectProgramStats(bs.progs);
        writer.WriteBpfStats(bs);
      }
      last_overhead_ts = now;
      next_overhead = now + cfg->sample.overhead_interval_ms * 1000000ULL;
    }

    if (now >= next_feature) {
      AnomalyFeatures f = BuildFeatures(*cfg, seq++, last_host, ebpf,
                                        selector.member_threads(), selector.member_processes());
      nlohmann::json j;
      to_json(j, f);
      writer.WriteAnomalyFeatures(j);
      phase.TickAnomaly(*cfg, f, f.ts_ns);
      next_feature = now + cfg->sample.base_feature_interval_ms * 1000000ULL;
    }

    if (now >= next_topk) {
      selector.Evaluate(*cfg);
      next_topk = now + cfg->targets.eval_interval_ms * 1000000ULL;
    }

    if (phase.deep_active() && now >= next_deep) {
      deep.Tick();
      next_deep = now + cfg->sample.deep_dump_interval_ms * 1000000ULL;
    }
    phase.TickDeep(*cfg, now);

    // Manual phase switching (SIGUSR1/SIGUSR2) — anomaly-free DEEP benchmarking.
    if (sig.deep_request.exchange(false)) phase.RequestDeep(*cfg, now);
    if (sig.base_request.exchange(false)) phase.RequestBase(*cfg, now);

    // keep the recorder producer's interval in sync with the phase (BASE= fine,
    // DEEP=deep_fine).
    uint64_t want_ms = phase.deep_active() ? cfg->sample.deep_fine_interval_ms
                                           : cfg->sample.fine_interval_ms;
    if (want_ms != cur_interval_ms) {
      ebpf.SetSnapshotInterval(want_ms);
      cur_interval_ms = want_ms;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  phase.Shutdown(*cfg, NowNs());
  ebpf.StopSnapshotter();
  ebpf.Close();
  RestoreBpfStats(bpf_stats_prev);
  LogInfo("collector stopped");
  return 0;
}

}  // namespace etrace_diag