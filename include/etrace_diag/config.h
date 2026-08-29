#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

// eTrace-Diag configuration.
//
// Load order (highest precedence first):
//   1. command-line flags (--config, --output-dir, ...)
//   2. ETRACE_DIAG_* environment variables
//   3. --config JSON file
//   4. built-in defaults (DefaultConfig())
//
// All fields except the `misc` bag are runtime-reloadable via SIGHUP.

namespace etrace_diag {

struct SampleTunables {
  uint64_t base_host_interval_ms = 1000;
  uint64_t base_feature_interval_ms = 1000;
  uint64_t fine_interval_ms = 100;
  uint64_t deep_fine_interval_ms = 20;
  uint64_t deep_dump_interval_ms = 1000;
  uint64_t profile_freq_hz = 99;
  uint32_t offcpu_sample_rate = 16;  // max off-CPU stack captures per thread/s
  uint32_t iofile_sample_rate = 4;   // 1/N vfs_read/vfs_write sampling
  uint64_t overhead_interval_ms = 1000;  // self-overhead sampling cadence
};

struct WindowTunables {
  uint64_t pre_anomaly_seconds = 60;
  uint64_t post_anomaly_seconds = 180;
  uint64_t ring_backlog_seconds = 90;
  uint32_t end_debounce_samples = 3;
  uint64_t end_grace_seconds = 5;
};

struct TargetWeights {
  double cpu = 0.35;
  double swch = 0.15;  // "switch" is a reserved word in some toolchains
  double io = 0.20;
  double fault = 0.15;
  double lock = 0.15;
};

struct TargetsTunables {
  uint32_t max_targets = 64;          // total thread ceiling on `targets` map
  bool auto_scale = true;             // derive thread budget from hardware
  uint32_t min_targets = 4;           // floor for auto-scaled thread budget
  uint32_t per_proc_threads = 4;      // top threads per selected process
  double concurrency_factor = 2.0;    // threads worth watching per logical core
  uint64_t eval_interval_ms = 5000;   // re-rank cadence (sliding-window step)
  uint64_t window_seconds = 30;       // rolling score window span
  uint32_t enter_rank = 12;           // process rank threshold to join
  uint32_t leave_rank = 20;           // process rank threshold to leave
  uint32_t hold_periods = 3;          // consecutive eval confirmations
  uint64_t min_residency_seconds = 10;
  std::vector<uint32_t> pinned;
  TargetWeights weights;
};

struct ModelTunables {
  std::string anomaly_url = "ws://127.0.0.1:9001/anomaly";
  uint64_t anomaly_timeout_ms = 5000;
  std::string causal_url = "ws://127.0.0.1:9002/causal";
  uint64_t causal_timeout_ms = 30000;
  std::string adapter = "ws";  // "ws" | "onnx"
};

struct OutputTunables {
  std::string dir;  // default: $PWD/out
  std::string metrics_format = "jsonl";
  std::string profile_format = "folded";
};

struct MiscTunables {
  std::string log_level = "info";
  std::vector<std::string> categories = {"cpu", "io", "memory", "lock", "syscall"};
  uint64_t pid_filter = 0;  // only this tid if set, else all
  bool enable_bpf_stats = true;  // attempt kernel.bpf_stats_enabled=1 at startup
};

struct Config {
  SampleTunables sample;
  WindowTunables window;
  TargetsTunables targets;
  ModelTunables model;
  OutputTunables output;
  MiscTunables misc;
};

// Built-in defaults.
Config DefaultConfig();

// Validate ranges; logs out-of-range corrections via a provided callback.
// Invalid values are clamped to safe bounds rather than rejected, so a
// malformed reload never destabilizes a running collector.
void Sanitize(Config& cfg);

// JSON <-> Config (dotted paths become nested JSON objects).
void to_json(nlohmann::json& j, const Config& c);
void from_json(const nlohmann::json& j, Config& c);

// Merge `overlay` (e.g. config file contents) over `base`, keeping `base`'s
// value wherever `overlay` does not supply one.
Config MergeConfig(const Config& base, const nlohmann::json& overlay);

// Apply ETRACE_DIAG_* environment variables on top of `c`. Returns true if
// any variable was applied.
bool ApplyEnvOverrides(Config& c);

}  // namespace etrace_diag