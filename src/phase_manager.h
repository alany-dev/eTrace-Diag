#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <nlohmann/json.hpp>

#include "collect/deep_collector.h"
#include "collect/ebpf_manager.h"
#include "collect/target_selector.h"
#include "etrace_diag/config.h"
#include "etrace_diag/model_client.h"
#include "etrace_diag/output_writer.h"
#include "model/features.h"

namespace etrace_diag {

enum class Phase { BASE, DEEP };

// BASE/DEEP phase state machine. Runs the anomaly model at its unchanged
// cadence in BOTH phases; starts/ends deep collection with debounce and a
// deterministic post-anomaly deadline; merges overlapping anomalies.
class PhaseManager {
 public:
  PhaseManager(OutputWriter& writer, DeepCollector& deep, std::unique_ptr<IModelClient> model);

  // Process one anomaly-feature tick (current config + features).
  void TickAnomaly(const Config& cfg, const AnomalyFeatures& f, uint64_t now_ns);

  // Process deep periodic duties (post drain / deadline check).
  void TickDeep(const Config& cfg, uint64_t now_ns);

  // Final sweep at shutdown (if still in DEEP, close out deterministically).
  void Shutdown(const Config& cfg, uint64_t now_ns);

  // Manual phase switching (SIGUSR1 -> DEEP, SIGUSR2 -> BASE); no anomaly
  // model needed for benchmarking the DEEP phase in isolation.
  void RequestDeep(const Config& cfg, uint64_t now_ns);
  void RequestBase(const Config& cfg, uint64_t now_ns);

  Phase phase() const { return phase_; }
  bool deep_active() const { return phase_ == Phase::DEEP; }
  uint64_t anomaly_start_ns() const { return anomaly_start_ts_; }

  // Summary of the most recent DEEP episode (for summary.txt / meta.json).
  nlohmann::json summary() const;

 private:
  void EnterDeep(const Config& cfg, uint64_t now_ns);
  void FinalizeDeep(const Config& cfg, uint64_t now_ns);
  void ExitDeep(uint64_t now_ns);

  OutputWriter& writer_;
  DeepCollector& deep_;
  std::unique_ptr<IModelClient> model_;

  Phase phase_ = Phase::BASE;
  int deep_ordinal_ = 0;

  uint64_t anomaly_start_ts_ = 0;
  uint64_t anomaly_end_ts_ = 0;
  uint64_t post_deadline_ns_ = 0;
  uint64_t first_false_ts_ = 0;
  uint32_t debounce_ = 0;
  std::vector<nlohmann::json> indicators_;

  nlohmann::json last_summary_;
};

}  // namespace etrace_diag