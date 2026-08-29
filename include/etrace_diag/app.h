#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include "etrace_diag/config.h"

namespace etrace_diag {

struct SignalState {
  std::atomic<bool> stop{false};
  std::atomic<bool> reload{false};
  std::atomic<bool> deep_request{false};  // SIGUSR1: manually enter DEEP
  std::atomic<bool> base_request{false};  // SIGUSR2: manually return to BASE
};

// Runs the data collector until `sig.stop` or `run_seconds` elapses
// (`run_seconds == 0` means run until a signal). `config_path` is re-read on
// SIGHUP (empty => env + defaults only). Returns 0 on clean shutdown,
// non-zero on fatal startup/shutdown error.
int RunCollector(const Config& initial, const std::string& config_path,
                 uint64_t run_seconds, SignalState& sig);

}  // namespace etrace_diag