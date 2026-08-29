#include "etrace_diag/config.h"

#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

namespace etrace_diag {

namespace {

// Clamp helpers.
uint64_t ClampU64(uint64_t v, uint64_t lo, uint64_t hi) { return v < lo ? lo : (v > hi ? hi : v); }
uint32_t ClampU32(uint32_t v, uint32_t lo, uint32_t hi) { return v < lo ? lo : (v > hi ? hi : v); }
double ClampD(double v, double lo, double hi) { return v < lo ? lo : (v > hi ? hi : v); }

// Simple env reader.
bool GetEnv(const char* name, std::string& out) {
  const char* v = std::getenv(name);
  if (!v) return false;
  out = v;
  return true;
}

uint64_t ParseU64(const std::string& s, uint64_t dflt) {
  if (s.empty()) return dflt;
  char* end = nullptr;
  unsigned long long v = std::strtoull(s.c_str(), &end, 10);
  if (end == s.c_str()) return dflt;
  return static_cast<uint64_t>(v);
}

double ParseD(const std::string& s, double dflt) {
  if (s.empty()) return dflt;
  char* end = nullptr;
  double v = std::strtod(s.c_str(), &end);
  if (end == s.c_str()) return dflt;
  return v;
}

bool ParseBool(const std::string& s, bool dflt) {
  if (s == "1" || s == "true" || s == "TRUE" || s == "on" || s == "yes") return true;
  if (s == "0" || s == "false" || s == "FALSE" || s == "off" || s == "no") return false;
  return dflt;
}

}  // namespace

Config DefaultConfig() {
  Config c;
  c.output.dir = "out";
  return c;
}

void Sanitize(Config& cfg) {
  cfg.sample.base_host_interval_ms = ClampU64(cfg.sample.base_host_interval_ms, 100, 60000);
  cfg.sample.base_feature_interval_ms = ClampU64(cfg.sample.base_feature_interval_ms, 100, 60000);
  cfg.sample.fine_interval_ms = ClampU64(cfg.sample.fine_interval_ms, 10, 5000);
  cfg.sample.deep_fine_interval_ms = ClampU64(cfg.sample.deep_fine_interval_ms, 5, 1000);
  cfg.sample.deep_dump_interval_ms = ClampU64(cfg.sample.deep_dump_interval_ms, 100, 60000);
  cfg.sample.profile_freq_hz = ClampU64(cfg.sample.profile_freq_hz, 1, 10000);
  cfg.sample.offcpu_sample_rate = ClampU32(cfg.sample.offcpu_sample_rate, 1, 100000);
  cfg.sample.iofile_sample_rate = ClampU32(cfg.sample.iofile_sample_rate, 1, 1000000);
  cfg.sample.overhead_interval_ms = ClampU64(cfg.sample.overhead_interval_ms, 100, 60000);

  cfg.targets.weights.cpu = ClampD(cfg.targets.weights.cpu, 0.0, 1.0);
  cfg.targets.weights.swch = ClampD(cfg.targets.weights.swch, 0.0, 1.0);
  cfg.targets.weights.io = ClampD(cfg.targets.weights.io, 0.0, 1.0);
  cfg.targets.weights.fault = ClampD(cfg.targets.weights.fault, 0.0, 1.0);
  cfg.targets.weights.lock = ClampD(cfg.targets.weights.lock, 0.0, 1.0);
  cfg.window.pre_anomaly_seconds = ClampU64(cfg.window.pre_anomaly_seconds, 1, 3600);
  cfg.window.post_anomaly_seconds = ClampU64(cfg.window.post_anomaly_seconds, 1, 3600);
  cfg.window.ring_backlog_seconds = ClampU64(cfg.window.ring_backlog_seconds, 1, 3600);
  cfg.window.end_debounce_samples = ClampU32(cfg.window.end_debounce_samples, 1, 1000);
  cfg.window.end_grace_seconds = ClampU64(cfg.window.end_grace_seconds, 0, 3600);

  cfg.targets.max_targets = ClampU32(cfg.targets.max_targets, 1, 1024);
  cfg.targets.min_targets = ClampU32(cfg.targets.min_targets, 1, cfg.targets.max_targets);
  cfg.targets.per_proc_threads = ClampU32(cfg.targets.per_proc_threads, 1, 256);
  cfg.targets.eval_interval_ms = ClampU64(cfg.targets.eval_interval_ms, 1000, 3600000);
  cfg.targets.window_seconds = ClampU64(cfg.targets.window_seconds, 1, 3600);
  cfg.targets.concurrency_factor = ClampD(cfg.targets.concurrency_factor, 0.5, 64.0);
  cfg.targets.enter_rank = ClampU32(cfg.targets.enter_rank, 1, 1024);
  cfg.targets.leave_rank = ClampU32(cfg.targets.leave_rank, cfg.targets.enter_rank, 4096);
  cfg.targets.hold_periods = ClampU32(cfg.targets.hold_periods, 1, 1000);
  cfg.targets.min_residency_seconds = ClampU64(cfg.targets.min_residency_seconds, 0, 36000);

  if (cfg.model.adapter != "ws" && cfg.model.adapter != "onnx") cfg.model.adapter = "ws";
  cfg.output.dir = cfg.output.dir.empty() ? "out" : cfg.output.dir;
}

void to_json(nlohmann::json& j, const Config& c) {
  j = nlohmann::json{
      {"sample",
       {{"base_host_interval_ms", c.sample.base_host_interval_ms},
        {"base_feature_interval_ms", c.sample.base_feature_interval_ms},
        {"fine_interval_ms", c.sample.fine_interval_ms},
        {"deep_fine_interval_ms", c.sample.deep_fine_interval_ms},
        {"deep_dump_interval_ms", c.sample.deep_dump_interval_ms},
        {"profile_freq_hz", c.sample.profile_freq_hz},
        {"offcpu_sample_rate", c.sample.offcpu_sample_rate},
        {"iofile_sample_rate", c.sample.iofile_sample_rate},
        {"overhead_interval_ms", c.sample.overhead_interval_ms}}},
      {"window",
       {{"pre_anomaly_seconds", c.window.pre_anomaly_seconds},
        {"post_anomaly_seconds", c.window.post_anomaly_seconds},
        {"ring_backlog_seconds", c.window.ring_backlog_seconds},
        {"end_debounce_samples", c.window.end_debounce_samples},
        {"end_grace_seconds", c.window.end_grace_seconds}}},
      {"targets",
       {{"max_targets", c.targets.max_targets},
        {"auto_scale", c.targets.auto_scale},
        {"min_targets", c.targets.min_targets},
        {"per_proc_threads", c.targets.per_proc_threads},
        {"concurrency_factor", c.targets.concurrency_factor},
        {"eval_interval_ms", c.targets.eval_interval_ms},
        {"window_seconds", c.targets.window_seconds},
        {"enter_rank", c.targets.enter_rank},
        {"leave_rank", c.targets.leave_rank},
        {"hold_periods", c.targets.hold_periods},
        {"min_residency_seconds", c.targets.min_residency_seconds},
        {"pinned", c.targets.pinned},
        {"weights",
         {{"cpu", c.targets.weights.cpu},
          {"switch", c.targets.weights.swch},
          {"io", c.targets.weights.io},
          {"fault", c.targets.weights.fault},
          {"lock", c.targets.weights.lock}}}}},
      {"model",
       {{"anomaly", {{"url", c.model.anomaly_url}, {"timeout_ms", c.model.anomaly_timeout_ms}}},
        {"causal", {{"url", c.model.causal_url}, {"timeout_ms", c.model.causal_timeout_ms}}},
        {"adapter", c.model.adapter}}},
      {"output",
       {{"dir", c.output.dir},
        {"metrics_format", c.output.metrics_format},
        {"profile_format", c.output.profile_format}}},
      {"misc",
       {{"log_level", c.misc.log_level},
        {"categories", c.misc.categories},
        {"pid_filter", c.misc.pid_filter},
        {"enable_bpf_stats", c.misc.enable_bpf_stats}}}};
}

void from_json(const nlohmann::json& j, Config& c) {
  if (j.contains("sample")) {
    auto& s = j["sample"];
    if (s.contains("base_host_interval_ms")) c.sample.base_host_interval_ms = s["base_host_interval_ms"];
    if (s.contains("base_feature_interval_ms")) c.sample.base_feature_interval_ms = s["base_feature_interval_ms"];
    if (s.contains("fine_interval_ms")) c.sample.fine_interval_ms = s["fine_interval_ms"];
    if (s.contains("deep_fine_interval_ms")) c.sample.deep_fine_interval_ms = s["deep_fine_interval_ms"];
    if (s.contains("deep_dump_interval_ms")) c.sample.deep_dump_interval_ms = s["deep_dump_interval_ms"];
    if (s.contains("profile_freq_hz")) c.sample.profile_freq_hz = s["profile_freq_hz"];
    if (s.contains("offcpu_sample_rate")) c.sample.offcpu_sample_rate = s["offcpu_sample_rate"];
    if (s.contains("iofile_sample_rate")) c.sample.iofile_sample_rate = s["iofile_sample_rate"];
    if (s.contains("overhead_interval_ms")) c.sample.overhead_interval_ms = s["overhead_interval_ms"];
  }
  if (j.contains("window")) {
    auto& w = j["window"];
    if (w.contains("pre_anomaly_seconds")) c.window.pre_anomaly_seconds = w["pre_anomaly_seconds"];
    if (w.contains("post_anomaly_seconds")) c.window.post_anomaly_seconds = w["post_anomaly_seconds"];
    if (w.contains("ring_backlog_seconds")) c.window.ring_backlog_seconds = w["ring_backlog_seconds"];
    if (w.contains("end_debounce_samples")) c.window.end_debounce_samples = w["end_debounce_samples"];
    if (w.contains("end_grace_seconds")) c.window.end_grace_seconds = w["end_grace_seconds"];
  }
  if (j.contains("targets")) {
    auto& t = j["targets"];
    if (t.contains("max_targets")) c.targets.max_targets = t["max_targets"];
    if (t.contains("auto_scale")) c.targets.auto_scale = t["auto_scale"];
    if (t.contains("min_targets")) c.targets.min_targets = t["min_targets"];
    if (t.contains("per_proc_threads")) c.targets.per_proc_threads = t["per_proc_threads"];
    if (t.contains("concurrency_factor")) c.targets.concurrency_factor = t["concurrency_factor"];
    if (t.contains("eval_interval_ms")) c.targets.eval_interval_ms = t["eval_interval_ms"];
    if (t.contains("window_seconds")) c.targets.window_seconds = t["window_seconds"];
    if (t.contains("enter_rank")) c.targets.enter_rank = t["enter_rank"];
    if (t.contains("leave_rank")) c.targets.leave_rank = t["leave_rank"];
    if (t.contains("hold_periods")) c.targets.hold_periods = t["hold_periods"];
    if (t.contains("min_residency_seconds")) c.targets.min_residency_seconds = t["min_residency_seconds"];
    if (t.contains("pinned")) c.targets.pinned = t["pinned"].get<std::vector<uint32_t>>();
    if (t.contains("weights")) {
      auto& w = t["weights"];
      if (w.contains("cpu")) c.targets.weights.cpu = w["cpu"];
      if (w.contains("switch")) c.targets.weights.swch = w["switch"];
      if (w.contains("io")) c.targets.weights.io = w["io"];
      if (w.contains("fault")) c.targets.weights.fault = w["fault"];
      if (w.contains("lock")) c.targets.weights.lock = w["lock"];
    }
  }
  if (j.contains("model")) {
    auto& m = j["model"];
    if (m.contains("anomaly")) {
      if (m["anomaly"].contains("url")) c.model.anomaly_url = m["anomaly"]["url"];
      if (m["anomaly"].contains("timeout_ms")) c.model.anomaly_timeout_ms = m["anomaly"]["timeout_ms"];
    }
    if (m.contains("causal")) {
      if (m["causal"].contains("url")) c.model.causal_url = m["causal"]["url"];
      if (m["causal"].contains("timeout_ms")) c.model.causal_timeout_ms = m["causal"]["timeout_ms"];
    }
    if (m.contains("adapter")) c.model.adapter = m["adapter"];
  }
  if (j.contains("output")) {
    auto& o = j["output"];
    if (o.contains("dir")) c.output.dir = o["dir"];
    if (o.contains("metrics_format")) c.output.metrics_format = o["metrics_format"];
    if (o.contains("profile_format")) c.output.profile_format = o["profile_format"];
  }
  if (j.contains("misc")) {
    auto& m = j["misc"];
    if (m.contains("log_level")) c.misc.log_level = m["log_level"];
    if (m.contains("categories")) c.misc.categories = m["categories"].get<std::vector<std::string>>();
    if (m.contains("pid_filter")) c.misc.pid_filter = m["pid_filter"];
    if (m.contains("enable_bpf_stats")) c.misc.enable_bpf_stats = m["enable_bpf_stats"];
  }
}

Config MergeConfig(const Config& base, const nlohmann::json& overlay) {
  // Serialize base to JSON, overlay the file contents onto it, re-parse.
  nlohmann::json merged;
  to_json(merged, base);
  merged.merge_patch(overlay);
  Config out;
  from_json(merged, out);
  return out;
}

bool ApplyEnvOverrides(Config& c) {
  bool applied = false;

  // (env var, setter)
  struct Entry {
    const char* env;
    void (*apply)(Config&, const std::string&);
  };

  static const Entry kEntries[] = {
      {"ETRACE_DIAG_SAMPLE_BASE_HOST_INTERVAL_MS",
       [](Config& x, const std::string& v) { x.sample.base_host_interval_ms = ParseU64(v, x.sample.base_host_interval_ms); }},
      {"ETRACE_DIAG_SAMPLE_BASE_FEATURE_INTERVAL_MS",
       [](Config& x, const std::string& v) { x.sample.base_feature_interval_ms = ParseU64(v, x.sample.base_feature_interval_ms); }},
      {"ETRACE_DIAG_SAMPLE_FINE_INTERVAL_MS",
       [](Config& x, const std::string& v) { x.sample.fine_interval_ms = ParseU64(v, x.sample.fine_interval_ms); }},
      {"ETRACE_DIAG_SAMPLE_DEEP_FINE_INTERVAL_MS",
       [](Config& x, const std::string& v) { x.sample.deep_fine_interval_ms = ParseU64(v, x.sample.deep_fine_interval_ms); }},
      {"ETRACE_DIAG_SAMPLE_DEEP_DUMP_INTERVAL_MS",
       [](Config& x, const std::string& v) { x.sample.deep_dump_interval_ms = ParseU64(v, x.sample.deep_dump_interval_ms); }},
      {"ETRACE_DIAG_SAMPLE_PROFILE_FREQ_HZ",
       [](Config& x, const std::string& v) { x.sample.profile_freq_hz = ParseU64(v, x.sample.profile_freq_hz); }},
      {"ETRACE_DIAG_SAMPLE_OFFCPU_SAMPLE_RATE",
       [](Config& x, const std::string& v) { x.sample.offcpu_sample_rate = (uint32_t)ParseU64(v, x.sample.offcpu_sample_rate); }},
      {"ETRACE_DIAG_SAMPLE_IOFILE_SAMPLE_RATE",
       [](Config& x, const std::string& v) { x.sample.iofile_sample_rate = (uint32_t)ParseU64(v, x.sample.iofile_sample_rate); }},
      {"ETRACE_DIAG_SAMPLE_OVERHEAD_INTERVAL_MS",
       [](Config& x, const std::string& v) { x.sample.overhead_interval_ms = ParseU64(v, x.sample.overhead_interval_ms); }},

      {"ETRACE_DIAG_WINDOW_PRE_ANOMALY_SECONDS",
       [](Config& x, const std::string& v) { x.window.pre_anomaly_seconds = ParseU64(v, x.window.pre_anomaly_seconds); }},
      {"ETRACE_DIAG_WINDOW_POST_ANOMALY_SECONDS",
       [](Config& x, const std::string& v) { x.window.post_anomaly_seconds = ParseU64(v, x.window.post_anomaly_seconds); }},
      {"ETRACE_DIAG_WINDOW_RING_BACKLOG_SECONDS",
       [](Config& x, const std::string& v) { x.window.ring_backlog_seconds = ParseU64(v, x.window.ring_backlog_seconds); }},
      {"ETRACE_DIAG_WINDOW_END_DEBOUNCE_SAMPLES",
       [](Config& x, const std::string& v) { x.window.end_debounce_samples = (uint32_t)ParseU64(v, x.window.end_debounce_samples); }},
      {"ETRACE_DIAG_WINDOW_END_GRACE_SECONDS",
       [](Config& x, const std::string& v) { x.window.end_grace_seconds = ParseU64(v, x.window.end_grace_seconds); }},

      {"ETRACE_DIAG_TARGETS_MAX_TARGETS",
       [](Config& x, const std::string& v) { x.targets.max_targets = (uint32_t)ParseU64(v, x.targets.max_targets); }},
      {"ETRACE_DIAG_TARGETS_ENTER_RANK",
       [](Config& x, const std::string& v) { x.targets.enter_rank = (uint32_t)ParseU64(v, x.targets.enter_rank); }},
      {"ETRACE_DIAG_TARGETS_LEAVE_RANK",
       [](Config& x, const std::string& v) { x.targets.leave_rank = (uint32_t)ParseU64(v, x.targets.leave_rank); }},
      {"ETRACE_DIAG_TARGETS_HOLD_PERIODS",
       [](Config& x, const std::string& v) { x.targets.hold_periods = (uint32_t)ParseU64(v, x.targets.hold_periods); }},
      {"ETRACE_DIAG_TARGETS_MIN_RESIDENCY_SECONDS",
       [](Config& x, const std::string& v) { x.targets.min_residency_seconds = ParseU64(v, x.targets.min_residency_seconds); }},
      {"ETRACE_DIAG_TARGETS_AUTO_SCALE",
       [](Config& x, const std::string& v) { x.targets.auto_scale = ParseBool(v, x.targets.auto_scale); }},
      {"ETRACE_DIAG_TARGETS_MIN_TARGETS",
       [](Config& x, const std::string& v) { x.targets.min_targets = (uint32_t)ParseU64(v, x.targets.min_targets); }},
      {"ETRACE_DIAG_TARGETS_PER_PROC_THREADS",
       [](Config& x, const std::string& v) { x.targets.per_proc_threads = (uint32_t)ParseU64(v, x.targets.per_proc_threads); }},
      {"ETRACE_DIAG_TARGETS_CONCURRENCY_FACTOR",
       [](Config& x, const std::string& v) { x.targets.concurrency_factor = ParseD(v, x.targets.concurrency_factor); }},
      {"ETRACE_DIAG_TARGETS_EVAL_INTERVAL_MS",
       [](Config& x, const std::string& v) { x.targets.eval_interval_ms = ParseU64(v, x.targets.eval_interval_ms); }},
      {"ETRACE_DIAG_TARGETS_WINDOW_SECONDS",
       [](Config& x, const std::string& v) { x.targets.window_seconds = ParseU64(v, x.targets.window_seconds); }},
      {"ETRACE_DIAG_TARGETS_WEIGHT_CPU",
       [](Config& x, const std::string& v) { x.targets.weights.cpu = ParseD(v, x.targets.weights.cpu); }},
      {"ETRACE_DIAG_TARGETS_WEIGHT_SWITCH",
       [](Config& x, const std::string& v) { x.targets.weights.swch = ParseD(v, x.targets.weights.swch); }},
      {"ETRACE_DIAG_TARGETS_WEIGHT_IO",
       [](Config& x, const std::string& v) { x.targets.weights.io = ParseD(v, x.targets.weights.io); }},
      {"ETRACE_DIAG_TARGETS_WEIGHT_FAULT",
       [](Config& x, const std::string& v) { x.targets.weights.fault = ParseD(v, x.targets.weights.fault); }},
      {"ETRACE_DIAG_TARGETS_WEIGHT_LOCK",
       [](Config& x, const std::string& v) { x.targets.weights.lock = ParseD(v, x.targets.weights.lock); }},

      {"ETRACE_DIAG_MODEL_ANOMALY_URL",
       [](Config& x, const std::string& v) { x.model.anomaly_url = v; }},
      {"ETRACE_DIAG_MODEL_ANOMALY_TIMEOUT_MS",
       [](Config& x, const std::string& v) { x.model.anomaly_timeout_ms = ParseU64(v, x.model.anomaly_timeout_ms); }},
      {"ETRACE_DIAG_MODEL_CAUSAL_URL",
       [](Config& x, const std::string& v) { x.model.causal_url = v; }},
      {"ETRACE_DIAG_MODEL_CAUSAL_TIMEOUT_MS",
       [](Config& x, const std::string& v) { x.model.causal_timeout_ms = ParseU64(v, x.model.causal_timeout_ms); }},
      {"ETRACE_DIAG_MODEL_ADAPTER",
       [](Config& x, const std::string& v) { x.model.adapter = v; }},

      {"ETRACE_DIAG_OUTPUT_DIR", [](Config& x, const std::string& v) { x.output.dir = v; }},
      {"ETRACE_DIAG_OUTPUT_METRICS_FORMAT",
       [](Config& x, const std::string& v) { x.output.metrics_format = v; }},
      {"ETRACE_DIAG_OUTPUT_PROFILE_FORMAT",
       [](Config& x, const std::string& v) { x.output.profile_format = v; }},

      {"ETRACE_DIAG_MISC_LOG_LEVEL", [](Config& x, const std::string& v) { x.misc.log_level = v; }},
      {"ETRACE_DIAG_MISC_PID_FILTER",
       [](Config& x, const std::string& v) { x.misc.pid_filter = ParseU64(v, x.misc.pid_filter); }},
      {"ETRACE_DIAG_MISC_ENABLE_BPF_STATS",
       [](Config& x, const std::string& v) { x.misc.enable_bpf_stats = ParseBool(v, x.misc.enable_bpf_stats); }},
  };

  for (const auto& e : kEntries) {
    std::string v;
    if (GetEnv(e.env, v)) {
      e.apply(c, v);
      applied = true;
    }
  }

  // List-valued overrides.
  std::string categories;
  if (GetEnv("ETRACE_DIAG_MISC_CATEGORIES", categories)) {
    c.misc.categories.clear();
    size_t start = 0;
    while (start <= categories.size()) {
      size_t comma = categories.find(',', start);
      std::string tok = categories.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
      if (!tok.empty()) c.misc.categories.push_back(tok);
      if (comma == std::string::npos) break;
      start = comma + 1;
    }
    applied = true;
  }
  std::string pinned;
  if (GetEnv("ETRACE_DIAG_TARGETS_PINNED", pinned)) {
    c.targets.pinned.clear();
    size_t start = 0;
    while (start <= pinned.size()) {
      size_t comma = pinned.find(',', start);
      std::string tok = pinned.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
      if (!tok.empty()) c.targets.pinned.push_back((uint32_t)ParseU64(tok, 0));
      if (comma == std::string::npos) break;
      start = comma + 1;
    }
    applied = true;
  }

  return applied;
}

}  // namespace etrace_diag