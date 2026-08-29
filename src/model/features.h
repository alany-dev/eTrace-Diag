#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "etrace_diag/metrics.h"

namespace etrace_diag {

// ---- anomaly-detection model interface ----
struct AnomalyFeatures {
  uint64_t seq = 0;
  uint64_t ts_ns = 0;
  HostSnapshot host;
  EbpfCounters ebpf;
  std::vector<ProcessRow> top_tasks;
};
void to_json(nlohmann::json& j, const AnomalyFeatures& f);

struct AnomalyIndicator {
  std::string type;
  double confidence = 0;
};

struct AnomalyResult {
  uint64_t seq = 0;
  uint64_t ts_ns = 0;
  bool is_anomaly = false;
  std::string type;
  double confidence = 0;
  std::vector<AnomalyIndicator> indicators;
};
void from_json(const nlohmann::json& j, AnomalyResult& r);

// ---- causal-inference model interface ----
// For the collection milestone the causal input is the full deep evidence
// bundle; the result is opaque (logged, not interpreted).
struct CausalContext {
  uint64_t seq = 0;
  uint64_t window_start_ns = 0;
  uint64_t window_end_ns = 0;
  nlohmann::json body;  // pre/post series + folded profiles + hotspots
};
void to_json(nlohmann::json& j, const CausalContext& c);

struct CausalResult {
  bool ok = false;
  std::string raw;  // opaque model reply
};
void from_json(const nlohmann::json& j, CausalResult& r);

}  // namespace etrace_diag