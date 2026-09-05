#include "phase_manager.h"

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "logging.h"

namespace etrace_diag {

PhaseManager::PhaseManager(OutputWriter& writer, DeepCollector& deep,
                           std::unique_ptr<IModelClient> model)
    : writer_(writer), deep_(deep), model_(std::move(model)) {}

void PhaseManager::EnterDeep(const Config& cfg, uint64_t now_ns) {
  deep_ordinal_++;
  anomaly_start_ts_ = now_ns;
  anomaly_end_ts_ = 0;
  post_deadline_ns_ = now_ns + cfg.window.post_anomaly_seconds * 1000000000ULL;
  first_false_ts_ = 0;
  debounce_ = 0;
  indicators_.clear();

  LogInfo("entering DEEP phase #%d at %llu (deadline +%llus)", deep_ordinal_,
          (unsigned long long)now_ns, (unsigned long long)cfg.window.post_anomaly_seconds);

  if (!deep_.Enter(deep_ordinal_, now_ns, cfg)) {
    LogError("DEEP entry failed; staying in BASE");
    phase_ = Phase::BASE;
    return;
  }
  phase_ = Phase::DEEP;
}

void PhaseManager::FinalizeDeep(const Config& cfg, uint64_t now_ns) {
  nlohmann::json summary;
  summary["v"] = 2;
  summary["anomaly_start_ts"] = anomaly_start_ts_;
  summary["anomaly_end_ts"] = anomaly_end_ts_;
  summary["post_deadline_ts"] = post_deadline_ns_;
  summary["deep_ordinal"] = deep_ordinal_;
  summary["deep_indicators"] = indicators_;

  deep_.Finalize(cfg, summary);

  // Causal inference: body carries the full evidence bundle (ADR-0004); the
  // model replies with a structured diagnosis persisted as diagnosis.json.
  nlohmann::json evidence = writer_.BuildEvidence(deep_ordinal_);
  evidence["anomaly_start_ts"] = anomaly_start_ts_;
  evidence["anomaly_end_ts"] = anomaly_end_ts_;
  evidence["deep_ordinal"] = deep_ordinal_;
  evidence["deep_indicators"] = indicators_;
  evidence["post_deadline_ts"] = post_deadline_ns_;

  CausalContext ctx;
  ctx.seq = deep_ordinal_;
  ctx.window_start_ns = anomaly_start_ts_ > cfg.window.pre_anomaly_seconds * 1000000000ULL
                            ? anomaly_start_ts_ - cfg.window.pre_anomaly_seconds * 1000000000ULL
                            : 0;
  ctx.window_end_ns = now_ns;
  ctx.body = evidence;
  try {
    CausalResult r = model_->InferCausal(ctx);
    summary["causal"] = {{"ok", r.ok}, {"raw", r.raw}};
    if (r.ok && !r.raw.empty()) {
      std::string path = writer_.session_dir() + "/diagnosis.json";
      FILE* f = fopen(path.c_str(), "w");
      if (f) {
        fwrite(r.raw.data(), 1, r.raw.size(), f);
        fclose(f);
        LogInfo("diagnosis written to %s", path.c_str());
      } else {
        LogWarn("cannot write diagnosis.json: %s", strerror(errno));
      }
    }
  } catch (const std::exception& e) {
    summary["causal"] = {{"ok", false}, {"error", e.what()}};
  }

  last_summary_ = summary;
  writer_.WriteMeta(summary);
  writer_.WriteSummary(summary.dump(2) + "\n");
  LogInfo("DEEP phase #%d finalized (ordinal=%d, start=%llu, end=%llu)",
          deep_ordinal_, deep_ordinal_, (unsigned long long)anomaly_start_ts_,
          (unsigned long long)anomaly_end_ts_);
}

void PhaseManager::ExitDeep(uint64_t /*now_ns*/) {
  deep_.Exit();
  phase_ = Phase::BASE;
  LogInfo("returned to BASE phase");
}

void PhaseManager::TickAnomaly(const Config& cfg, const AnomalyFeatures& f, uint64_t now_ns) {
  AnomalyResult r;
  try {
    r = model_->InferAnomaly(f);
  } catch (const std::exception& e) {
    // reserved onnx adapter throws; treat as no-anomaly
    LogWarn("InferAnomaly failed: %s (treated as no-anomaly)", e.what());
    r.is_anomaly = false;
    r.seq = f.seq;
    r.ts_ns = f.ts_ns;
  }

  if (phase_ == Phase::BASE) {
    if (r.is_anomaly) {
      EnterDeep(cfg, now_ns);
    }
    return;
  }

  // DEEP: anomaly results only feed indicators; they never re-time the window.
  if (r.is_anomaly) {
    indicators_.push_back({{"type", r.type}, {"confidence", r.confidence}});
    debounce_ = 0;
    first_false_ts_ = 0;
  } else {
    if (debounce_ == 0) first_false_ts_ = now_ns;
    debounce_++;
    if (debounce_ >= cfg.window.end_debounce_samples && anomaly_end_ts_ == 0) {
      anomaly_end_ts_ = first_false_ts_;
    }
  }
}

void PhaseManager::TickDeep(const Config& cfg, uint64_t now_ns) {
  if (phase_ != Phase::DEEP) return;
  if (now_ns >= post_deadline_ns_) {
    FinalizeDeep(cfg, now_ns);
    ExitDeep(now_ns);
  }
}

void PhaseManager::Shutdown(const Config& cfg, uint64_t now_ns) {
  if (phase_ == Phase::DEEP) {
    FinalizeDeep(cfg, now_ns);
    ExitDeep(now_ns);
  }
}

void PhaseManager::RequestDeep(const Config& cfg, uint64_t now_ns) {
  if (phase_ == Phase::BASE) EnterDeep(cfg, now_ns);
}

void PhaseManager::RequestBase(const Config& cfg, uint64_t now_ns) {
  if (phase_ == Phase::DEEP) {
    FinalizeDeep(cfg, now_ns);
    ExitDeep(now_ns);
  }
}

nlohmann::json PhaseManager::summary() const { return last_summary_; }

}  // namespace etrace_diag