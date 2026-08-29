#pragma once

#include <memory>

#include "etrace_diag/config.h"
#include "model/features.h"

namespace etrace_diag {

class IModelClient {
 public:
  virtual ~IModelClient() = default;

  virtual AnomalyResult InferAnomaly(const AnomalyFeatures& f) = 0;
  virtual CausalResult InferCausal(const CausalContext& c) = 0;
};

// Factory selected by cfg.model.adapter ("ws" | "onnx").
std::unique_ptr<IModelClient> MakeModelClient(const Config& cfg);

}  // namespace etrace_diag