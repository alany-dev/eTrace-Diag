#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "collect/ebpf_manager.h"
#include "etrace_diag/config.h"
#include "etrace_diag/output_writer.h"

namespace etrace_diag {

// Two-level top-k selector. The kernel `targets` map ends up holding a bounded
// set of thread tids = top-K processes x top-per_proc_threads threads each.
// Every DEEP/fine hook filters by that map in-kernel.
//
// Hardware adaptation: Probe() reads online logical CPUs, cgroup CPU quota and
// cpuset effective CPUs, and total memory, then derives the thread budget from
// EFFECTIVE CONCURRENCY (how many threads can actually run simultaneously on
// this device — online cores capped by cgroup limits) times concurrency_factor,
// further clamped by the flight-recorder ring capacity and [min, max]_targets.
//
// Scoring uses a SLIDING WINDOW of cumulative per-tid kernel counters: each
// eval pushes a full snapshot and scores the delta against the oldest snapshot
// still inside window_seconds, so an abrupt spike does not churn membership (a
// process must stay hot across the whole window). A rank band (enter_rank <
// leave_rank) + hold_periods + min_residency keep series continuous.
class TargetSelector {
 public:
  struct HardwareProbe {
    uint32_t online_cpus = 0;   // sysconf(_SC_NPROCESSORS_ONLN)
    uint32_t quota_cpus = 0;    // cgroup cpu.max quota/period (0 = unlimited)
    uint32_t cpuset_cpus = 0;   // cpuset effective/cpus list count (0 = none)
    uint32_t eff_cpus = 0;      // effective concurrency: min(online, quota?, cpuset?)
    uint64_t mem_total_kb = 0;  // /proc/meminfo MemTotal
    uint32_t ring_slots = 0;    // recorder map max_entries
  };

  TargetSelector(EbpfManager& ebpf, OutputWriter& writer);

  // Adds config-pinned tids into the target set at startup.
  void ApplyPinned(const Config& cfg);

  // Probe hardware once and derive the thread budget from `cfg` (auto_scale,
  // concurrency_factor, ring/backlog). Re-call after a config reload.
  void Probe(const Config& cfg);

  uint32_t thread_budget() const { return thread_budget_; }
  const HardwareProbe& hw() const { return hw_; }

  // One scoring/evaluation pass. Returns true if membership changed.
  bool Evaluate(const Config& cfg);

  const std::unordered_set<uint32_t>& member_threads() const { return members_; }
  const std::unordered_set<uint32_t>& member_processes() const { return procs_; }

 private:
  struct Counters {
    uint64_t on_cpu_ns = 0;
    uint64_t sw_vol = 0, sw_invol = 0;
    uint64_t io_ops = 0, io_bytes = 0;
    uint64_t pf_minor = 0, pf_major = 0;
    uint64_t lock_waits = 0;
  };
  struct ProcAgg {
    uint64_t on_cpu_ns = 0, sw = 0, io_ops = 0, io_bytes = 0, faults = 0, lock = 0;
  };
  struct ProcState {
    uint32_t tgid = 0;
    bool member = false;
    bool pinned_proc = false;
    uint32_t good_streak = 0, bad_streak = 0;
    uint64_t joined_ns = 0;
  };
  struct Snapshot {
    uint64_t ts_ns = 0;
    std::unordered_map<uint32_t, Counters> c;
  };
  struct ThreadScore {
    uint32_t tid = 0;
    double score = 0;
  };

  Counters ReadTid(uint32_t tid);
  void Join(uint32_t tid, uint32_t tgid, double score, uint32_t proc_rank);
  void Leave(uint32_t tid, uint32_t proc_rank);
  uint64_t NowNs() const;

  EbpfManager& ebpf_;
  OutputWriter& writer_;
  HardwareProbe hw_;
  uint32_t thread_budget_ = 16;
  std::unordered_map<uint32_t, ProcState> pstate_;  // tgid -> process hysteresis
  std::unordered_set<uint32_t> pinned_;             // config pinned tids
  std::unordered_set<uint32_t> members_;           // current target tids
  std::unordered_set<uint32_t> procs_;              // current selected tgids
  std::deque<Snapshot> history_;                    // sliding window
};

}  // namespace etrace_diag