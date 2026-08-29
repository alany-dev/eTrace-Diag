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

  // Reads a single process's VmRSS (kB) from /proc/<pid>/status. Returns 0 on
  // failure. Used only for the target set (mm->rss is not BPF-readable on 6.6).
  static uint64_t ReadVmRss(uint32_t pid);

  // Reads /proc/<pid>/comm (16-byte task name). Returns "" on failure.
  static std::string ReadComm(uint32_t pid);
};

}  // namespace etrace_diag