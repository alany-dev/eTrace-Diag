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

#include "collect/bpf_values.h"
#include "collect/deep_collector.h"
#include "collect/ebpf_manager.h"
#include "collect/gpu_metrics.h"
#include "collect/host_metrics.h"
#include "collect/network_metrics.h"
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

// Aggregate current-target counters from the per-tid maps. CPU/switch/fault
// come from the already-read process table where possible; I/O and lock still
// come from the full block_io / lock_st maps, and lock_lat_ns is filled from
// lock_st.lat_sum (never the old constant 0).
EbpfCounters BuildEbpfCounters(EbpfManager& ebpf, uint64_t ts_ns,
                               const std::unordered_set<uint32_t>& members,
                               const std::vector<ProcessRow>& process_table) {
  EbpfCounters c;
  c.ts_ns = ts_ns;

  std::unordered_map<u32, const ProcessRow*> by_tid;
  by_tid.reserve(process_table.size());
  for (const auto& r : process_table) by_tid[r.pid] = &r;

  for (u32 tid : members) {
    EbpfPerTidStats t;
    t.tid = tid;
    SwitchVal sw = {};
    if (ebpf.Slice("switches")->LookupPercpuSum(&tid, &sw)) {
      t.nr_sw_vol = sw.vol;
      t.nr_sw_invol = sw.invol;
    }
    BlockIoVal bi = {};
    if (ebpf.Slice("block_io")->LookupPercpuSum(&tid, &bi)) {
      t.io_ops = bi.ops;
      t.io_bytes = bi.bytes;
    }
    FaultsVal ft = {};
    if (ebpf.Slice("faults")->LookupPercpuSum(&tid, &ft)) {
      t.pf_minor = ft.minor;
      t.pf_major = ft.major;
    }
    LatStatVal13 lk = {};
    if (ebpf.Slice("lock_st")->LookupPercpuSum(&tid, &lk)) {
      t.lock_waits = lk.count;
      t.lock_lat_ns = lk.lat_sum;  // must be populated, not left at 0
    }
    u64 on_cpu = 0;
    if (!ebpf.Slice("on_cpu_ns")->LookupPercpuSum(&tid, &on_cpu)) on_cpu = 0;
    t.on_cpu_ns = on_cpu;
    if (t.on_cpu_ns == 0) {
      auto it = by_tid.find(tid);
      if (it != by_tid.end()) {
        const double ticks_per_s = (double)sysconf(_SC_CLK_TCK);
        t.on_cpu_ns = ticks_per_s > 0
                          ? (u64)((it->second->utime + it->second->stime) * 1e9 / ticks_per_s)
                          : 0;
      }
    }

    c.on_cpu_ns_total += t.on_cpu_ns;
    c.switch_total += t.nr_sw_vol + t.nr_sw_invol;
    c.io_ops_total += t.io_ops;
    c.io_bytes_total += t.io_bytes;
    c.minor_faults_total += t.pf_minor;
    c.major_faults_total += t.pf_major;
    c.lock_waits_total += t.lock_waits;
    c.per_tid.push_back(t);
  }
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
  nlohmann::json e = {{"v", 2}, {"ts_ns", ts_ns}, {"kswapd_active", m.kswapd_active},
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
    nlohmann::json e = {{"v", 2}, {"ts_ns", ev.ts}, {"pid", ev.pid}, {"comm", comm}};
    writer.WriteMemoryEvent(e);
  }
  last_seq = seq;
}

// One aggregated ProcessRow per selected process (the canonical top-K process
// table), summed from the host process table's per-thread rows. RSS values
// are REUSED from the already-read rows (no second /proc read).
std::vector<ProcessRow> BuildTopTasks(const std::vector<ProcessRow>& table,
                                      const std::unordered_set<uint32_t>& procs) {
  std::unordered_map<uint32_t, ProcessRow> agg;
  for (const auto& r : table) {
    uint32_t g = r.tgid ? r.tgid : r.pid;
    if (!procs.count(g)) continue;
    ProcessRow& a = agg[g];
    if (!a.tgid) {
      a.tgid = g;
      a.pid = g;
      a.state = r.state;
      a.start_time = r.start_time;
      a.rss_valid = r.rss_valid;
      a.rss_kb = r.rss_kb;
    }
    if (r.pid == g) {  // main thread: keep its comm
      std::memcpy(a.comm, r.comm, 15);
      a.comm[15] = 0;
    }
    a.utime += r.utime;
    a.stime += r.stime;
    a.nvcsw += r.nvcsw;
    a.nivcsw += r.nivcsw;
    a.minflt += r.minflt;
    a.majflt += r.majflt;
    a.total_vm += r.total_vm;
  }
  std::vector<ProcessRow> out;
  out.reserve(agg.size());
  for (auto& [g, a] : agg) out.push_back(a);
  std::sort(out.begin(), out.end(), [](const ProcessRow& a, const ProcessRow& b) {
    return (a.utime + a.stime) > (b.utime + b.stime);
  });
  return out;
}

AnomalyFeatures BuildFeatures(const Config& cfg, uint64_t seq, const HostSnapshot& host,
                              const NetworkSnapshot& network, const GpuSnapshot& gpu,
                              const CgroupSnapshot& cgroup, EbpfManager& ebpf,
                              const std::unordered_set<uint32_t>& members,
                              const std::unordered_set<uint32_t>& procs,
                              const std::vector<ProcessRow>& process_table) {
  AnomalyFeatures f;
  f.seq = seq;
  f.ts_ns = host.ts_ns;
  f.host = host;
  f.network = network;
  f.gpu = gpu;
  f.cgroup = cgroup;

  // Focus filter (debug/benchmark): restrict host procs to one pid.
  if (cfg.misc.pid_filter) {
    f.host.procs.erase(
        std::remove_if(f.host.procs.begin(), f.host.procs.end(), [&](const ProcessRow& p) {
          return (p.tgid ? p.tgid : p.pid) != cfg.misc.pid_filter;
        }),
        f.host.procs.end());
  }

  f.ebpf = BuildEbpfCounters(ebpf, host.ts_ns, members, process_table);

  std::unordered_set<uint32_t> want = procs;
  if (cfg.misc.pid_filter) {
    want.clear();
    want.insert((uint32_t)cfg.misc.pid_filter);
  }
  f.top_tasks = BuildTopTasks(process_table, want);
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
  Logger::Instance().Init("", ParseLogLevel(initial.misc.log_level));
  // Every log line lands in the DB logs table from the very first message.
  Logger::Instance().SetSink([&writer](const std::string& line) { writer.WriteLogLine(line); });
  LogInfo("session dir: %s", writer.session_dir().c_str());

  std::string bpf_stats_prev;
  bool bpf_stats_ok = false;
  if (cfg->misc.enable_bpf_stats) {
    bpf_stats_ok = EnableBpfStats(bpf_stats_prev);
    LogInfo("kernel.bpf_stats_enabled=%s (previous=%s)", bpf_stats_ok ? "1" : "unavailable",
            bpf_stats_prev.empty() ? "unknown" : bpf_stats_prev.c_str());
  }

  // Optional programs are compile-time present in the skeleton but may miss
  // their kernel feature; autoload-off keeps a missing optional hook from
  // failing the whole skeleton load. Required always-on programs stay on.
  EbpfManager ebpf;
  if (!ebpf.Open()) {
    LogError("BPF skeleton open failed");
    return 1;
  }
  {
    // Programs the 5.15 verifier rejects at LOAD time are autoload-off; the
    // metrics they cover fall back to alternate instrumentation:
    //   file I/O  -> kprobe/kretprobe vfs_read/vfs_write fallback programs
    //   connect/accept/RTT -> raw-syscall enter/exit (already target-gated)
    std::vector<std::string> unavailable;
    ebpf.SetOptionalAutoload(
        {"fentry_vfs_read", "fexit_vfs_read", "fentry_vfs_write", "fexit_vfs_write",
         "kprobe_tcp_v4_connect", "kprobe_tcp_v6_connect",
         "kretprobe_inet_csk_accept", "kprobe_tcp_rcv_established"},
        &unavailable);
    for (const auto& u : unavailable) LogWarn("optional hook unavailable: %s", u.c_str());
  }
  if (!ebpf.Load()) {
    LogError("BPF load failed (kernel >= 6.6 with CONFIG_DEBUG_INFO_BTF required)");
    return 1;
  }

  // Push sampling config into the kernel + start the flight recorder.
  ebpf.WriteNcpus(PossibleCpus());
  ebpf.WriteSampleRateCfg(cfg->sample.offcpu_sample_rate, cfg->sample.iofile_sample_rate,
                          cfg->devices.net_event_sample_rate);
  if (!ebpf.StartSnapshotter(cfg->sample.fine_interval_ms)) {
    LogError("failed to start the flight-recorder snapshotter");
    return 1;
  }

  GpuMetrics gpu;
  gpu.Init(cfg->devices.gpu_source);

  TargetSelector selector(ebpf, writer);
  selector.ApplyPinned(*cfg);
  selector.Probe(*cfg);

  auto model = MakeModelClient(*cfg);
  DeepCollector deep(ebpf, writer, gpu);
  PhaseManager phase(writer, deep, std::move(model));

  uint64_t t0 = NowNs();
  uint64_t next_host = 0, next_feature = 0, next_topk = 0;
  uint64_t seq = 0;
  uint64_t next_overhead = 0;
  uint64_t last_overhead_ts = 0;
  uint64_t cur_interval_ms = cfg->sample.fine_interval_ms;
  HostSnapshot last_host;
  NetworkSnapshot last_network;
  GpuSnapshot last_gpu;
  CgroupSnapshot last_cgroup;
  std::vector<ProcessRow> process_table;

  while (!sig.stop.load()) {
    if (run_seconds &&
        NowNs() - t0 >= run_seconds * 1000000000ULL)
      break;

    if (sig.reload.exchange(false)) {
      std::string old_gpu_source = cfg->devices.gpu_source;
      cfg = ReloadConfig(initial, config_path);
      ebpf.WriteSampleRateCfg(cfg->sample.offcpu_sample_rate, cfg->sample.iofile_sample_rate,
                              cfg->devices.net_event_sample_rate);
      if (cfg->devices.gpu_source != old_gpu_source) {
        gpu.Close();
        gpu.Init(cfg->devices.gpu_source);
      }
      selector.Probe(*cfg);
      LogInfo("config reloaded (fine_interval_ms=%llu)",
              (unsigned long long)cfg->sample.fine_interval_ms);
    }

    uint64_t now = NowNs();

    if (now >= next_host) {
      last_host = HostMetrics::Snapshot();
      // One iterator pass per host tick: full table to the selector and
      // BuildFeatures; only a top-200 CPU-sorted COPY goes into host.procs.
      if (ebpf.ReadProcessTable(process_table)) {
        // RSS and the fine-grained fields come from the iter/task eBPF pass
        // itself (rss_stat/ioac/schedstat) — no per-thread /proc reads.
        std::vector<ProcessRow> top = process_table;
        std::sort(top.begin(), top.end(), [](const ProcessRow& a, const ProcessRow& b) {
          return (a.utime + a.stime) > (b.utime + b.stime);
        });
        if (top.size() > 200) top.resize(200);
        last_host.procs = std::move(top);
      }
      last_network = NetworkMetrics::Snapshot(last_host.ts_ns, cfg->devices.network_enabled);
      last_gpu = gpu.Snapshot(last_host.ts_ns);
      last_cgroup = HostMetrics::ReadCgroup(last_host.ts_ns);
      writer.BeginBatch();
      writer.WriteHostRow(last_host, last_network, last_gpu, last_cgroup);
      DumpMemEvents(ebpf, writer, last_host.ts_ns);
      DumpOomEvents(ebpf, writer);
      writer.CommitBatch();
      next_host = now + cfg->sample.base_host_interval_ms * 1000000ULL;
    }

    if (now >= next_overhead) {
      ProcOverhead po = BuildProcOverhead(now);
      writer.BeginBatch();
      writer.WriteProcOverhead(po);
      if (bpf_stats_ok) {
        BpfStatsSnapshot bs;
        bs.ts_ns = now;
        bs.interval_ns = last_overhead_ts ? now - last_overhead_ts : 0;
        bs.stats_enabled = true;
        ebpf.CollectProgramStats(bs.progs);
        writer.WriteBpfStats(bs);
      }
      writer.CommitBatch();
      last_overhead_ts = now;
      next_overhead = now + cfg->sample.overhead_interval_ms * 1000000ULL;
    }

    // Target set + latest process table refresh BEFORE phase transitions.
    deep.SetTargetProcesses(selector.member_threads());
    deep.SetProcessTable(process_table);

    if (now >= next_feature) {
      AnomalyFeatures f = BuildFeatures(*cfg, seq++, last_host, last_network, last_gpu,
                                        last_cgroup, ebpf, selector.member_threads(),
                                        selector.member_processes(), process_table);
      nlohmann::json j;
      to_json(j, f);
      writer.BeginBatch();
      writer.WriteAnomalyFeatures(j);
      writer.CommitBatch();
      phase.TickAnomaly(*cfg, f, f.ts_ns);
      next_feature = now + cfg->sample.base_feature_interval_ms * 1000000ULL;
    }
    if (now >= next_topk) {
      if (!process_table.empty()) selector.Evaluate(*cfg, process_table, now);
      next_topk = now + cfg->targets.eval_interval_ms * 1000000ULL;
    }

    // DEEP periodic duties are self-paced inside Tick (ring/process drain at
    // deep_dump_interval_ms, GPU at deep_gpu_interval_ms).
    deep.Tick(now, *cfg);
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
  gpu.Close();
  ebpf.Close();
  writer.Close();  // WAL checkpoint + 关闭，主文件自含（前端 sql.js 只读主文件）
  RestoreBpfStats(bpf_stats_prev);
  return 0;
}

}  // namespace etrace_diag
