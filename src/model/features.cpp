#include "model/features.h"

#include <nlohmann/json.hpp>

namespace etrace_diag {

using nlohmann::json;

void to_json(json& j, const AnomalyFeatures& f) {
  json top = json::array();
  for (const auto& p : f.top_tasks) top.push_back(p);
  json host;
  to_json(host, f.host);
  json ebpf;
  to_json(ebpf, f.ebpf);
  j = json{{"v", 1},
           {"seq", f.seq},
           {"ts_ns", f.ts_ns},
           {"host", host},
           {"ebpf", ebpf},
           {"top_tasks", top}};
}

void from_json(const json& j, AnomalyResult& r) {
  if (j.contains("seq")) r.seq = j["seq"];
  if (j.contains("ts_ns")) r.ts_ns = j["ts_ns"];
  if (j.contains("is_anomaly")) r.is_anomaly = j["is_anomaly"];
  if (j.contains("type")) r.type = j["type"];
  if (j.contains("confidence")) r.confidence = j["confidence"];
  if (j.contains("indicators") && j["indicators"].is_array()) {
    r.indicators.clear();
    for (const auto& e : j["indicators"]) {
      AnomalyIndicator ind;
      if (e.contains("type")) ind.type = e["type"];
      if (e.contains("confidence")) ind.confidence = e["confidence"];
      r.indicators.push_back(std::move(ind));
    }
  }
}

void to_json(json& j, const CausalContext& c) {
  j = json{{"v", 1},
           {"seq", c.seq},
           {"window_start_ns", c.window_start_ns},
           {"window_end_ns", c.window_end_ns},
           {"evidence", c.body}};
}

void from_json(const json& j, CausalResult& r) {
  // The causal model's reply is opaque in this milestone; capture the raw text.
  if (j.is_string()) {
    r.raw = j.get<std::string>();
    r.ok = true;
  } else {
    r.raw = j.dump();
    r.ok = true;
  }
}

}  // namespace etrace_diag