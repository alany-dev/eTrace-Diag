#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <bpf/libbpf.h>

#include "collect/ebpf_manager.h"
#include "collect/gpu_metrics.h"
#include "etrace_diag/config.h"
#include "etrace_diag/output_writer.h"

namespace etrace_diag {

// DEEP-phase orchestrator: attach deep links + on-CPU profiler, extract the
// pre-anomaly flight-recorder window, incrementally drain the post window,
// sample /proc evidence + GPU process evidence, and finalize the deep map
// dumps + summary. Optional hooks (profiler, offcpu, process-exit cleanup,
// fentry/fexit file I/O, network) degrade to capability records — DEEP still
// runs with the required syscall pair.
class DeepCollector {
 public:
  DeepCollector(EbpfManager& ebpf, OutputWriter& writer, GpuMetrics& gpu);

  bool Enter(int ordinal, uint64_t anomaly_start_ns, const Config& cfg);
  // Called every main-loop iteration while DEEP is active. Internally paced by
  // deep_dump_interval_ms (ring/process drain) and deep_gpu_interval_ms (GPU).
  void Tick(uint64_t now_ns, const Config& cfg);
  void Finalize(const Config& cfg, nlohmann::json& summary_json);
  void Exit();

  bool active() const { return active_; }

  // Current target tid set, refreshed by app before phase transitions.
  void SetTargetProcesses(const std::unordered_set<uint32_t>& tids) { targets_ = tids; }

  // Latest iter/task process table (single eBPF pass per host tick). DEEP
  // process evidence is derived from it — no per-thread /proc reads.
  void SetProcessTable(const std::vector<ProcessRow>& table) { process_table_ = table; }

 private:
  struct Capability {
    std::string name;
    bool available = false;
    std::string error;
  };

  bool AttachDeepLinks(std::vector<Capability>& caps);
  void CloseDeepLinks();
  bool OpenProfiler(uint64_t freq_hz);
  void CloseProfiler();
  float PercentileUs(const uint32_t* hist, int bins, uint64_t base_ns, uint64_t factor,
                     double q) const;
  void ResetEpisodeMaps();
  void SaveLockHotBaseline();
  void ExtractPre(uint64_t anomaly_start_ns, const Config& cfg);
  void DrainPost();
  void DrainProcesses(uint64_t now_ns);
  void DrainGpu(uint64_t now_ns);
  void DumpDeepMaps(const Config& cfg);

  // Returns folded string for a (stack id, pid, user) triple; cache key is the
  // triple, not the raw sid (sid space is shared across user/kernel stacks).
  std::string Folded(u32 sid, u32 pid, bool user);

  EbpfManager& ebpf_;
  OutputWriter& writer_;
  GpuMetrics& gpu_;
  int ordinal_ = 0;
  bool active_ = false;
  uint64_t anomaly_start_ns_ = 0;
  uint64_t prev_head_ = 0;
  uint64_t pre_interval_ms_ = 100;
  uint64_t post_interval_ms_ = 20;
  uint64_t next_dump_ns_ = 0;
  uint64_t next_gpu_ns_ = 0;
  std::vector<struct bpf_link*> deep_links_;
  std::vector<int> perf_fds_;
  std::unordered_set<uint32_t> targets_;
  std::vector<ProcessRow> process_table_;
  // stack id -> folded, keyed by (sid<<2 | kind) so user/kernel don't collide.
  std::unordered_map<uint64_t, std::string> fold_cache_;
  std::vector<uint64_t> stack_buf_;                        // ip[127]
  std::unordered_map<uint64_t, uint64_t> lock_hot_base_;   // addr -> count baseline
  std::vector<Capability> capabilities_;
};

}  // namespace etrace_diag
