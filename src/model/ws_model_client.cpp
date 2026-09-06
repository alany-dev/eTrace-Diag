#include "etrace_diag/model_client.h"

#include "logging.h"
#include "model/ws_client.h"

namespace etrace_diag {

namespace {

// WebSocket-backed model client. Connections are made lazily and re-attempted
// on each call after failure (the model service may not be up yet).
// Per design: an anomaly InerAnomaly timeout/transport error is treated as
// is_anomaly=false (no spurious DEEP), logged at most once per N failures.
class WsModelClient : public IModelClient {
 public:
  explicit WsModelClient(const Config& cfg)
      : anomaly_url_(cfg.model.anomaly_url),
        causal_url_(cfg.model.causal_url),
        anomaly_timeout_(cfg.model.anomaly_timeout_ms),
        causal_timeout_(cfg.model.causal_timeout_ms) {}

  AnomalyResult InferAnomaly(const AnomalyFeatures& f) override {
    AnomalyResult r;
    r.seq = f.seq;
    r.ts_ns = f.ts_ns;
    std::string out;
    if (!RoundTrip(anomaly_, anomaly_url_, f, out, anomaly_timeout_)) {
      NoteFailure();
      return r;  // is_anomaly=false
    }
    Failures(0);
    try {
      nlohmann::json j = nlohmann::json::parse(out);
      from_json(j, r);
    } catch (const std::exception& e) {
      LogWarn("anomaly model: unparsable reply: %s", e.what());
    }
    return r;
  }

  CausalResult InferCausal(const CausalContext& c) override {
    CausalResult r;
    std::string out;
    if (!RoundTrip(causal_, causal_url_, c, out, causal_timeout_)) {
      LogWarn("causal model: request failed (service down or timeout)");
      return r;
    }
    r.raw = out;
    r.ok = true;
    return r;
  }

 private:
  template <typename T>
  bool RoundTrip(WsClient& ws, const std::string& url, const T& msg, std::string& out,
                 uint64_t timeout_ms) {
    if (!ws.IsOpen()) {
      if (!ws.Connect(url, timeout_ms)) {
        LogWarn("ws roundtrip: connect to %s failed", url.c_str());
        ws.Close();
        return false;
      }
    }
    nlohmann::json j;
    to_json(j, msg);
    std::string payload = j.dump();
    if (!ws.SendText(payload)) {
      LogWarn("ws roundtrip: send failed (%llu bytes)", (unsigned long long)payload.size());
      ws.Close();
      return false;
    }
    if (!ws.RecvText(out, timeout_ms)) {
      LogWarn("ws roundtrip: recv failed (timeout or close)");
      ws.Close();
      return false;
    }
    return true;
  }

  void NoteFailure() {
    uint64_t n = Failures(-1) + 1;
    Failures(n);
    if (n == 1 || (n % 100) == 0) {
      LogWarn("anomaly model unreachable (%llu consecutive failures); treating as no-anomaly",
              (unsigned long long)n);
    }
  }

  // Static failure counter (simple, single-threaded collector loop).
  static uint64_t Failures(int64_t set) {
    static uint64_t n = 0;
    if (set >= 0) n = (uint64_t)set;
    return n;
  }

  std::string anomaly_url_;
  std::string causal_url_;
  uint64_t anomaly_timeout_;
  uint64_t causal_timeout_;
  WsClient anomaly_;
  WsClient causal_;
};

}  // namespace

std::unique_ptr<IModelClient> MakeModelClient(const Config& cfg) {
  if (cfg.model.adapter == "onnx") {
    // Reserved ONNX adapter (anomaly detector). Causal stays WS for now.
    extern std::unique_ptr<IModelClient> MakeOnnxModelClient(const Config&);
    return MakeOnnxModelClient(cfg);
  }
  return std::make_unique<WsModelClient>(cfg);
}

}  // namespace etrace_diag