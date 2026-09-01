#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "etrace_diag/metrics.h"

namespace etrace_diag {

// Optional GPU metrics provider: NVIDIA NVML via runtime dlopen (no link-time
// dependency on libnvidia-ml), falling back to DRM sysfs (AMD/Intel), or off.
// Provider/library/field failures degrade to unavailable rows or zeroed fields
// with clear valid_mask bits — never throw, never fail-fast the collector.
class GpuMetrics {
 public:
  GpuMetrics() = default;
  ~GpuMetrics() { Close(); }

  GpuMetrics(const GpuMetrics&) = delete;
  GpuMetrics& operator=(const GpuMetrics&) = delete;

  // source: "auto" | "off" | "nvml" | "drm".
  // Returns true when a real backend is active ("off" always succeeds).
  // On failure the object still produces an unavailable row on Snapshot.
  bool Init(const std::string& source);

  GpuSnapshot Snapshot(uint64_t ts_ns);
  void BeginDeep();
  std::vector<DeepGpuProcessRow> SnapshotProcesses(const std::unordered_set<uint32_t>& tgids,
                                                   uint64_t collector_ts_ns);
  void Close();

 private:
  struct NvmlApi;  // forward; defined in the .cpp
  bool InitNvml();
  bool InitDrm();
  GpuDeviceRow NvmlDevice(uint32_t index) const;
  GpuDeviceRow DrmDevice(const std::string& card_path) const;
  std::vector<DeepGpuProcessRow> NvmlProcesses(const std::unordered_set<uint32_t>& tgids,
                                               uint64_t collector_ts_ns);

  std::string source_;      // normalized: off | nvml | drm | auto(unavailable)
  std::string active_;      // actual backend in use: off | nvml | drm | ""
  std::string fail_reason_;
  NvmlApi* nvml_ = nullptr;
  std::vector<std::string> drm_cards_;
  uint32_t nvml_count_ = 0;
};

}  // namespace etrace_diag
