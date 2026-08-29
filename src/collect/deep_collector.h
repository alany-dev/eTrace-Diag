#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <bpf/libbpf.h>

#include "collect/ebpf_manager.h"
#include "etrace_diag/config.h"
#include "etrace_diag/output_writer.h"

namespace etrace_diag {

// DEEP-phase orchestrator: attach deep links + on-CPU profiler, extract the
// pre-anomaly flight-recorder window, incrementally drain the post window,
// and finalize the deep map dumps + summary.
class DeepCollector {
 public:
  DeepCollector(EbpfManager& ebpf, OutputWriter& writer);

  bool Enter(int ordinal, uint64_t anomaly_start_ns, const Config& cfg);
  void Tick();
  void Finalize(const Config& cfg, nlohmann::json& summary_json);
  void Exit();

  bool active() const { return active_; }

 private:
  bool AttachDeepLinks();
  void CloseDeepLinks();
  bool OpenProfiler(uint64_t freq_hz);
  void CloseProfiler();
  float PercentileUs(const uint32_t* hist, int bins, uint64_t base_ns, uint64_t factor,
                     double q) const;
  void ExtractPre(uint64_t anomaly_start_ns, const Config& cfg);
  void DrainPost();
  void DumpDeepMaps(const Config& cfg);

  // Returns folded string for a stack id, caching per stack_id.
  std::string Folded(u32 sid, u32 pid, bool user);

  EbpfManager& ebpf_;
  OutputWriter& writer_;
  int ordinal_ = 0;
  bool active_ = false;
  uint64_t anomaly_start_ns_ = 0;
  uint64_t prev_head_ = 0;
  uint64_t pre_interval_ms_ = 100;
  uint64_t post_interval_ms_ = 20;
  std::vector<struct bpf_link*> deep_links_;
  std::vector<int> perf_fds_;
  std::unordered_map<uint32_t, std::string> fold_cache_;  // stack_id -> folded
  std::vector<uint64_t> stack_buf_;                        // ip[127]
};

}  // namespace etrace_diag