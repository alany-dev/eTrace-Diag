#include <memory>
#include <stdexcept>

#include "etrace_diag/model_client.h"

namespace etrace_diag {

// Reserved ONNX Runtime adapter for the anomaly detector. No fake results:
// InferAnomaly throws until ONNX Runtime is actually linked (later milestone).
class OnnxModelClient : public IModelClient {
 public:
  explicit OnnxModelClient(const Config& /*cfg*/) {}

  AnomalyResult InferAnomaly(const AnomalyFeatures& /*f*/) override {
    throw std::logic_error("ONNX runtime not linked (reserved adapter)");
  }

  CausalResult InferCausal(const CausalContext& /*c*/) override {
    // Causal inference stays WebSocket-backed; the onnx adapter only covers the
    // anomaly detector. Return an unset result rather than fabricating one.
    return CausalResult{};
  }
};

std::unique_ptr<IModelClient> MakeOnnxModelClient(const Config& cfg) {
  return std::make_unique<OnnxModelClient>(cfg);
}

}  // namespace etrace_diag