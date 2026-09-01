// Build-time configuration probe: verifies default.json parsing, load order
// (JSON < env), and Sanitize clamping. Exits non-zero on any mismatch.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#include "etrace_diag/config.h"

using namespace etrace_diag;

static int failures = 0;

#define CHECK(cond, msg)                \
  do {                                  \
    if (!(cond)) {                      \
      fprintf(stderr, "FAIL: %s\n", msg); \
      ++failures;                       \
    }                                   \
  } while (0)

int main(int argc, char** argv) {
  Config base = DefaultConfig();

  std::string cfg_path = argc > 1 ? argv[1] : "config/default.json";
  std::ifstream f(cfg_path);
  if (!f.good()) {
    fprintf(stderr, "FAIL: cannot open %s\n", cfg_path.c_str());
    return 1;
  }
  nlohmann::json j;
  f >> j;

  Config cfg = MergeConfig(base, j);

  CHECK(cfg.sample.base_host_interval_ms == 1000, "base_host_interval_ms default");
  CHECK(cfg.sample.fine_interval_ms == 100, "fine_interval_ms default");
  CHECK(cfg.sample.deep_fine_interval_ms == 20, "deep_fine_interval_ms default");
  CHECK(cfg.sample.profile_freq_hz == 99, "profile_freq_hz default");
  CHECK(cfg.window.pre_anomaly_seconds == 60, "pre default");
  CHECK(cfg.window.post_anomaly_seconds == 180, "post default");
  CHECK(cfg.targets.max_targets == 64, "max_targets default");
  CHECK(cfg.targets.enter_rank == 12, "enter_rank default");
  CHECK(cfg.targets.leave_rank == 20, "leave_rank default");
  CHECK(cfg.targets.auto_scale == true, "auto_scale default");
  CHECK(cfg.targets.min_targets == 4, "min_targets default");
  CHECK(cfg.targets.per_proc_threads == 4, "per_proc_threads default");
  CHECK(cfg.targets.eval_interval_ms == 5000, "eval_interval_ms default");
  CHECK(cfg.targets.window_seconds == 30, "window_seconds default");
  CHECK(cfg.targets.concurrency_factor == 2.0, "concurrency_factor default");
  CHECK(cfg.model.anomaly_url == "ws://127.0.0.1:9001/anomaly", "anomaly url");
  CHECK(cfg.model.adapter == "ws", "adapter default");
  CHECK(cfg.devices.network_enabled == true, "devices.network_enabled default");
  CHECK(cfg.devices.deep_network_enabled == true, "devices.deep_network_enabled default");
  CHECK(cfg.devices.gpu_source == "auto", "devices.gpu_source default");
  CHECK(cfg.devices.deep_gpu_enabled == true, "devices.deep_gpu_enabled default");
  CHECK(cfg.devices.deep_gpu_interval_ms == 100, "devices.deep_gpu_interval_ms default");
  CHECK(cfg.devices.net_event_sample_rate == 16, "devices.net_event_sample_rate default");
  CHECK(cfg.targets.weights.cpu == 0.35, "weight cpu");
  CHECK(cfg.misc.categories.size() == 5, "categories count");

  // Round-trip: to_json -> from_json preserves values.
  nlohmann::json rt;
  to_json(rt, cfg);
  Config cfg2;
  from_json(rt, cfg2);
  CHECK(cfg2.sample.base_host_interval_ms == cfg.sample.base_host_interval_ms, "to_json/from_json roundtrip");

  // Env override beats JSON.
  setenv("ETRACE_DIAG_SAMPLE_FINE_INTERVAL_MS", "50", 1);
  setenv("ETRACE_DIAG_DEVICES_GPU_SOURCE", "off", 1);
  setenv("ETRACE_DIAG_DEVICES_DEEP_GPU_INTERVAL_MS", "7", 1);   // clamps to 10
  setenv("ETRACE_DIAG_DEVICES_NET_EVENT_SAMPLE_RATE", "200000", 1);  // clamps to 100000
  Config cfg3 = cfg;
  bool applied = ApplyEnvOverrides(cfg3);
  CHECK(applied, "env override applied");
  CHECK(cfg3.sample.fine_interval_ms == 50, "env override value");
  CHECK(cfg3.devices.gpu_source == "off", "env gpu_source override");
  Sanitize(cfg3);
  CHECK(cfg3.devices.deep_gpu_interval_ms == 10, "gpu interval clamp");
  CHECK(cfg3.devices.net_event_sample_rate == 100000, "net rate clamp");
  CHECK(cfg3.devices.gpu_source == "off", "gpu source accepted after sanitize");

  // Sanitize rejects an unknown gpu source back to auto.
  Config bad_src = cfg;
  bad_src.devices.gpu_source = "cuda";
  Sanitize(bad_src);
  CHECK(bad_src.devices.gpu_source == "auto", "unknown gpu source -> auto");
  Config bad = cfg;
  bad.targets.leave_rank = 5;  // below enter_rank
  Sanitize(bad);
  CHECK(bad.targets.leave_rank >= bad.targets.enter_rank, "sanitize rank band");

  if (failures == 0) {
    printf("config_probe: ok (base_host=%llu fine=%llu deep_fine=%llu)\n",
           (unsigned long long)cfg.sample.base_host_interval_ms,
           (unsigned long long)cfg.sample.fine_interval_ms,
           (unsigned long long)cfg.sample.deep_fine_interval_ms);
    return 0;
  }
  fprintf(stderr, "config_probe: %d failure(s)\n", failures);
  return 1;
}