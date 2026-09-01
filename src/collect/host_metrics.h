#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "etrace_diag/metrics.h"

namespace etrace_diag {

// Reads host-level metrics from /proc and /sys. No privileges required.
class HostMetrics {
 public:
  // Fills cpu/load/mem/vm/psi/disks (NOT procs — procs come from the iter/task
  // BPF link). Timestamp uses CLOCK_MONOTONIC ns to match bpf_ktime_get_ns().
  static HostSnapshot Snapshot();

  // Reads the collector's own cgroup v2 directory (located once via
  // /proc/self/cgroup + /proc/self/mountinfo). available=false on cgroup v1 or
  // unreadable paths — never fail-fast.
  static CgroupSnapshot ReadCgroup(uint64_t ts_ns);

  // Reads a single process's VmRSS (kB) from /proc/<pid>/status. Returns false
  // on failure (rss_kb untouched). Used only for the target set.
  static bool ReadVmRss(uint32_t pid, uint64_t& rss_kb);

  // Reads /proc/<pid>/comm (16-byte task name). Returns "" on failure.
  static std::string ReadComm(uint32_t pid);
};

}  // namespace etrace_diag
