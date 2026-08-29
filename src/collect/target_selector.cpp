#include "collect/target_selector.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <time.h>
#include <unistd.h>

#include "collect/host_metrics.h"
#include "logging.h"

namespace etrace_diag {

namespace {

// Mirrors of the per-tid PERCPU_HASH values in bpf/etrace.bpf.c.
struct SwitchVal { u32 vol; u32 invol; };
struct BlockIoVal { u64 ops; u64 bytes; u64 lat_sum; u32 hist[13]; };
struct FaultsVal { u32 minor; u32 major; };
struct LatStatVal { u64 count; u64 lat_sum; u32 hist[13]; };

std::string ReadFileTrim(const std::string& path) {
  std::ifstream f(path);
  if (!f.good()) return {};
  std::string s;
  std::getline(f, s);
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
  return s;
}

// "0-3,5,8-9" -> number of CPUs listed.
uint32_t ParseCpuListCount(const std::string& s) {
  uint32_t n = 0;
  size_t i = 0;
  while (i < s.size()) {
    size_t comma = s.find(',', i);
    std::string tok = s.substr(i, comma == std::string::npos ? std::string::npos : comma - i);
    size_t dash = tok.find('-');
    if (dash == std::string::npos) {
      if (!tok.empty()) n++;
    } else {
      long a = strtol(tok.substr(0, dash).c_str(), nullptr, 10);
      long b = strtol(tok.substr(dash + 1).c_str(), nullptr, 10);
      if (b >= a) n += (uint32_t)(b - a + 1);
    }
    if (comma == std::string::npos) break;
    i = comma + 1;
  }
  return n;
}

// Effective cgroup CPU quota (cpus). 0 = unlimited/unknown.
uint32_t ReadQuotaCpus() {
  std::string s = ReadFileTrim("/sys/fs/cgroup/cpu.max");
  if (!s.empty()) {
    std::istringstream is(s);
    std::string quota, period;
    is >> quota >> period;
    if (quota == "max") return 0;
    double q = strtod(quota.c_str(), nullptr);
    double p = strtod(period.c_str(), nullptr);
    if (p > 0 && q >= 0) return q == 0 ? 0 : (uint32_t)ceil(q / p);
    return 0;
  }
  std::string q = ReadFileTrim("/sys/fs/cgroup/cpu/cpu.cfs_quota_us");
  std::string p = ReadFileTrim("/sys/fs/cgroup/cpu/cpu.cfs_period_us");
  if (!q.empty() && !p.empty()) {
    double qd = strtod(q.c_str(), nullptr);
    double pd = strtod(p.c_str(), nullptr);
    if (qd < 0) return 0;  // -1 = unlimited
    if (pd > 0 && qd > 0) return (uint32_t)ceil(qd / pd);
  }
  return 0;
}

uint32_t ReadCpusetCpus() {
  std::string s = ReadFileTrim("/sys/fs/cgroup/cpuset.cpus.effective");
  if (s.empty()) s = ReadFileTrim("/sys/fs/cgroup/cpuset/cpuset.cpus");
  return s.empty() ? 0 : ParseCpuListCount(s);
}

uint64_t ReadMemTotalKb() {
  std::ifstream f("/proc/meminfo");
  std::string line;
  while (std::getline(f, line)) {
    if (line.rfind("MemTotal:", 0) == 0) {
      unsigned long long kb = 0;
      if (sscanf(line.c_str() + 9, "%llu", &kb) == 1) return kb;
    }
  }
  return 0;
}

// Weighted score from a window's absolute deltas. cpu_util is saturating; the
// rest are rate-normalized to fixed reference scales then saturated to [0,1].
double ComputeScore(const Config& cfg, double window_s, uint64_t cpu_ns, uint64_t sum_sw,
                    uint64_t io_ops, uint64_t io_bytes, uint64_t faults, uint64_t lock_waits) {
  const double ref_switch = 10000.0, ref_io = 10000.0, ref_iobw = 1073741824.0,
               ref_fault = 10000.0, ref_lock = 1000.0;
  auto sat = [](double v) { return v < 0 ? 0.0 : (v > 1 ? 1.0 : v); };
  double cpu_util = (double)cpu_ns / (window_s * 1e9);
  if (cpu_util < 0) cpu_util = 0;
  if (cpu_util > 1) cpu_util = 1;
  double sw = (double)sum_sw / window_s;
  double io_rate = (double)io_ops / window_s;
  double io_bw = (double)io_bytes / window_s;
  double fault = (double)faults / window_s;
  double lock = (double)lock_waits / window_s;
  return cfg.targets.weights.cpu * cpu_util +
         cfg.targets.weights.swch * sat(sw / ref_switch) +
         cfg.targets.weights.io * ((sat(io_rate / ref_io) + sat(io_bw / ref_iobw)) / 2) +
         cfg.targets.weights.fault * sat(fault / ref_fault) +
         cfg.targets.weights.lock * sat(lock / ref_lock);
}

}  // namespace

TargetSelector::TargetSelector(EbpfManager& ebpf, OutputWriter& writer)
    : ebpf_(ebpf), writer_(writer) {}

uint64_t TargetSelector::NowNs() const {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void TargetSelector::Probe(const Config& cfg) {
  hw_ = {};
  hw_.online_cpus = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
  hw_.quota_cpus = ReadQuotaCpus();
  hw_.cpuset_cpus = ReadCpusetCpus();
  hw_.mem_total_kb = ReadMemTotalKb();

  struct bpf_map* r = ebpf_.Map("recorder");
  hw_.ring_slots = r ? (uint32_t)bpf_map__max_entries(r) : 32768;

  uint32_t eff = hw_.online_cpus ? hw_.online_cpus : 1;
  if (hw_.quota_cpus && hw_.quota_cpus < eff) eff = hw_.quota_cpus;
  if (hw_.cpuset_cpus && hw_.cpuset_cpus < eff) eff = hw_.cpuset_cpus;
  hw_.eff_cpus = eff;

  const auto& t = cfg.targets;
  uint32_t budget = t.max_targets;
  if (t.auto_scale) {
    uint32_t by_concurrency = (uint32_t)ceil((double)hw_.eff_cpus * t.concurrency_factor);
    uint64_t fine_ms = cfg.sample.fine_interval_ms ? cfg.sample.fine_interval_ms : 100;
    uint64_t backlog_s = cfg.window.ring_backlog_seconds ? cfg.window.ring_backlog_seconds : 90;
    uint64_t ticks = backlog_s * 1000 / fine_ms;
    uint32_t by_ring = hw_.ring_slots / (ticks ? (uint32_t)ticks : 1);
    budget = std::min(by_concurrency, by_ring);
    budget = std::min(budget, t.max_targets);
    if (budget < t.min_targets) budget = t.min_targets;
    if (budget > t.max_targets) budget = t.max_targets;
  }
  thread_budget_ = budget ? budget : 1;
  LogInfo("target budget: online=%u quota=%u cpuset=%u eff_cpus=%u mem=%lluKB ring=%u -> threads=%u",
          hw_.online_cpus, hw_.quota_cpus, hw_.cpuset_cpus, hw_.eff_cpus,
          (unsigned long long)hw_.mem_total_kb, hw_.ring_slots, thread_budget_);
}

TargetSelector::Counters TargetSelector::ReadTid(uint32_t tid) {
  Counters c;
  u64 v = 0;
  if (ebpf_.Slice("on_cpu_ns")->LookupPercpuSum(&tid, &v)) c.on_cpu_ns = v;
  SwitchVal sw = {};
  if (ebpf_.Slice("switches")->LookupPercpuSum(&tid, &sw)) {
    c.sw_vol = sw.vol;
    c.sw_invol = sw.invol;
  }
  BlockIoVal bi = {};
  if (ebpf_.Slice("block_io")->LookupPercpuSum(&tid, &bi)) {
    c.io_ops = bi.ops;
    c.io_bytes = bi.bytes;
  }
  FaultsVal ft = {};
  if (ebpf_.Slice("faults")->LookupPercpuSum(&tid, &ft)) {
    c.pf_minor = ft.minor;
    c.pf_major = ft.major;
  }
  LatStatVal lk = {};
  if (ebpf_.Slice("lock_st")->LookupPercpuSum(&tid, &lk)) c.lock_waits = lk.count;
  return c;
}

void TargetSelector::ApplyPinned(const Config& cfg) {
  for (u32 tid : cfg.targets.pinned) {
    if (!tid || pinned_.count(tid)) continue;
    pinned_.insert(tid);
    uint32_t tgid = 0;
    std::ifstream f("/proc/" + std::to_string(tid) + "/status");
    std::string line;
    while (std::getline(f, line)) {
      if (line.rfind("Tgid:", 0) == 0) {
        tgid = (uint32_t)strtoul(line.c_str() + 5, nullptr, 10);
        break;
      }
    }
    if (!tgid) tgid = tid;
    std::string comm = HostMetrics::ReadComm(tid);
    ebpf_.AddTarget(tid, 1 /*pinned*/, tgid, comm.c_str());
    members_.insert(tid);
    procs_.insert(tgid);
    auto& st = pstate_[tgid];
    st.tgid = tgid;
    st.member = true;
    st.pinned_proc = true;
    st.joined_ns = NowNs();
  }
}

void TargetSelector::Join(uint32_t tid, uint32_t tgid, double score, uint32_t proc_rank) {
  std::string comm = HostMetrics::ReadComm(tid);
  ebpf_.AddTarget(tid, 2 /*dynamic*/, tgid, comm.c_str());
  nlohmann::json e = {{"v", 1},         {"ts_ns", NowNs()}, {"action", "join"},
                      {"tid", tid},     {"tgid", tgid},     {"comm", comm},
                      {"score", score}, {"rank", proc_rank}};
  writer_.WriteTargetsEvent(e);
  LogInfo("target join tid=%u tgid=%u comm=%s score=%.4f rank=%u", tid, tgid, comm.c_str(),
          score, proc_rank);
}

void TargetSelector::Leave(uint32_t tid, uint32_t proc_rank) {
  ebpf_.RemoveTarget(tid);
  std::string comm = HostMetrics::ReadComm(tid);
  nlohmann::json e = {{"v", 1},      {"ts_ns", NowNs()}, {"action", "leave"},
                      {"tid", tid},  {"comm", comm},     {"rank", proc_rank}};
  writer_.WriteTargetsEvent(e);
  LogInfo("target leave tid=%u rank=%u", tid, proc_rank);
}

bool TargetSelector::Evaluate(const Config& cfg) {
  uint64_t now = NowNs();
  const auto& t = cfg.targets;

  // 1. tid -> tgid from the kernel process iter (full table, one pass).
  std::vector<ProcessRow> proctable;
  ebpf_.ReadProcessTable(proctable);
  std::unordered_map<uint32_t, uint32_t> tid2tgid;
  tid2tgid.reserve(proctable.size());
  for (const auto& r : proctable) tid2tgid[r.pid] = r.tgid ? r.tgid : r.pid;

  // 2. Full per-tid cumulative counter snapshot.
  Snapshot snap;
  snap.ts_ns = now;
  struct TidCollect { std::vector<uint32_t> tids; } col;
  ebpf_.Slice("on_cpu_ns")->ForEach(
      [&col](const void* key, const void*) { col.tids.push_back(*(const uint32_t*)key); });
  for (uint32_t tid : col.tids) snap.c[tid] = ReadTid(tid);

  // 3. Slide the window: drop snapshots older than window_seconds.
  history_.push_back(std::move(snap));
  while (history_.size() > 2 &&
         now - history_.front().ts_ns > t.window_seconds * 1000000000ULL)
    history_.pop_front();
  if (history_.size() < 2) return false;  // first eval: establish baseline only

  const Snapshot& base = history_.front();
  const Snapshot& cur = history_.back();
  double window_s = (double)(cur.ts_ns - base.ts_ns) / 1e9;
  if (window_s <= 0) window_s = 1.0;

  // 4. Per-thread delta + per-process aggregate over the window.
  std::unordered_map<uint32_t, Counters> thread_delta;
  std::unordered_map<uint32_t, double> tid_score;
  std::unordered_map<uint32_t, ProcAgg> pacc;
  for (const auto& [tid, c] : cur.c) {
    Counters d = c;
    auto it = base.c.find(tid);
    if (it != base.c.end()) {
      const Counters& b = it->second;
      d.on_cpu_ns = c.on_cpu_ns >= b.on_cpu_ns ? c.on_cpu_ns - b.on_cpu_ns : 0;
      d.sw_vol = c.sw_vol >= b.sw_vol ? c.sw_vol - b.sw_vol : 0;
      d.sw_invol = c.sw_invol >= b.sw_invol ? c.sw_invol - b.sw_invol : 0;
      d.io_ops = c.io_ops >= b.io_ops ? c.io_ops - b.io_ops : 0;
      d.io_bytes = c.io_bytes >= b.io_bytes ? c.io_bytes - b.io_bytes : 0;
      d.pf_minor = c.pf_minor >= b.pf_minor ? c.pf_minor - b.pf_minor : 0;
      d.pf_major = c.pf_major >= b.pf_major ? c.pf_major - b.pf_major : 0;
      d.lock_waits = c.lock_waits >= b.lock_waits ? c.lock_waits - b.lock_waits : 0;
    }
    thread_delta[tid] = d;
    uint64_t sw = d.sw_vol + d.sw_invol;
    uint64_t faults = d.pf_minor + d.pf_major;
    tid_score[tid] =
        ComputeScore(cfg, window_s, d.on_cpu_ns, sw, d.io_ops, d.io_bytes, faults, d.lock_waits);
    uint32_t tgid = tid2tgid.count(tid) ? tid2tgid[tid] : tid;
    auto& a = pacc[tgid];
    a.on_cpu_ns += d.on_cpu_ns;
    a.sw += sw;
    a.io_ops += d.io_ops;
    a.io_bytes += d.io_bytes;
    a.faults += faults;
    a.lock += d.lock_waits;
  }

  // 5. Process score + rank.
  std::vector<std::pair<uint32_t, double>> pscored;
  pscored.reserve(pacc.size());
  for (const auto& [tgid, a] : pacc)
    pscored.push_back(
        {tgid, ComputeScore(cfg, window_s, a.on_cpu_ns, a.sw, a.io_ops, a.io_bytes, a.faults,
                            a.lock)});
  std::sort(pscored.begin(), pscored.end(),
            [](const auto& x, const auto& y) { return x.second > y.second; });
  std::unordered_map<uint32_t, uint32_t> rank;
  rank.reserve(pscored.size());
  for (size_t i = 0; i < pscored.size(); ++i) rank[pscored[i].first] = (uint32_t)(i + 1);

  // 6. Ensure state entries for every observed process.
  for (const auto& [tgid, a] : pacc)
    if (!pstate_.count(tgid)) pstate_[tgid] = {tgid, false, false, 0, 0, 0};

  // 7. Process-level hysteresis (rank band + hold periods + min residency).
  std::vector<uint32_t> leave_list, join_list;
  for (auto& [tgid, st] : pstate_) {
    if (st.pinned_proc) continue;
    uint32_t r = rank.count(tgid) ? rank[tgid] : 0xFFFFFFFFu;
    if (st.member) {
      if (r > t.leave_rank) st.bad_streak++; else st.bad_streak = 0;
      uint64_t residency = now - st.joined_ns;
      if (st.bad_streak >= t.hold_periods &&
          residency >= t.min_residency_seconds * 1000000000ULL)
        leave_list.push_back(tgid);
    } else {
      if (r <= t.enter_rank) st.good_streak++; else st.good_streak = 0;
      if (st.good_streak >= t.hold_periods) join_list.push_back(tgid);
    }
  }

  bool changed = false;
  for (uint32_t tgid : leave_list) {
    pstate_[tgid].member = false;
    pstate_[tgid].bad_streak = 0;
  }

  // 8. Join up to the process budget (thread_budget_ / per_proc_threads).
  uint32_t proc_budget = thread_budget_ / (t.per_proc_threads ? t.per_proc_threads : 1);
  if (proc_budget < 1) proc_budget = 1;
  uint32_t member_proc = 0;
  for (const auto& [tgid, st] : pstate_)
    if (st.member || st.pinned_proc) member_proc++;
  std::sort(join_list.begin(), join_list.end(),
            [&](uint32_t a, uint32_t b) { return rank[a] < rank[b]; });
  for (uint32_t tgid : join_list) {
    if (member_proc >= proc_budget) break;
    pstate_[tgid].member = true;
    pstate_[tgid].good_streak = 0;
    pstate_[tgid].joined_ns = now;
    member_proc++;
  }

  // 9. Desired thread set: pinned + top threads of each selected process.
  std::unordered_set<uint32_t> desired(pinned_.begin(), pinned_.end());

  std::unordered_map<uint32_t, std::vector<ThreadScore>> threads_by_proc;
  for (const auto& [tid, d] : thread_delta) {
    uint32_t tgid = tid2tgid.count(tid) ? tid2tgid[tid] : tid;
    threads_by_proc[tgid].push_back({tid, tid_score[tid]});
  }
  for (auto& [tgid, vec] : threads_by_proc)
    std::sort(vec.begin(), vec.end(),
              [](const ThreadScore& a, const ThreadScore& b) { return a.score > b.score; });

  for (const auto& [tgid, st] : pstate_) {
    if (!st.pinned_proc && !st.member) continue;
    auto it = threads_by_proc.find(tgid);
    if (it == threads_by_proc.end()) continue;
    uint32_t take = t.per_proc_threads;
    for (const auto& ts : it->second) {
      if (take == 0) break;
      if (desired.size() >= thread_budget_ && !desired.count(ts.tid)) break;
      desired.insert(ts.tid);
      take--;
    }
  }

  // Fallback: never leave the recorder empty when there is anything to watch.
  if (desired.empty() && !pscored.empty()) {
    uint32_t top = pscored[0].first;
    pstate_[top].member = true;
    pstate_[top].joined_ns = now;
    auto it = threads_by_proc.find(top);
    if (it != threads_by_proc.end()) {
      uint32_t take = t.per_proc_threads;
      for (const auto& ts : it->second) {
        if (take == 0) break;
        if (desired.size() >= thread_budget_) break;
        desired.insert(ts.tid);
        take--;
      }
    }
  }

  // 10. Apply membership diff to the kernel `targets` map.
  std::unordered_set<uint32_t> cur_set(members_.begin(), members_.end());
  for (uint32_t tid : members_) {
    if (desired.count(tid)) continue;
    uint32_t tgid = tid2tgid.count(tid) ? tid2tgid[tid] : tid;
    Leave(tid, rank.count(tgid) ? rank[tgid] : 0);
    changed = true;
  }
  for (uint32_t tid : desired) {
    if (cur_set.count(tid)) continue;
    uint32_t tgid = tid2tgid.count(tid) ? tid2tgid[tid] : tid;
    Join(tid, tgid, tid_score.count(tid) ? tid_score[tid] : 0.0,
         rank.count(tgid) ? rank[tgid] : 0);
    changed = true;
  }

  members_ = desired;

  procs_.clear();
  for (uint32_t tid : members_) procs_.insert(tid2tgid.count(tid) ? tid2tgid[tid] : tid);

  return changed;
}

}  // namespace etrace_diag