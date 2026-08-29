#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <fstream>
#include <string>

#include "etrace_diag/app.h"
#include "etrace_diag/config.h"
#include "logging.h"

using namespace etrace_diag;

namespace {

void PrintUsage(const char* argv0) {
  fprintf(stderr,
          "usage: %s [options]\n"
          "  --config <path>         JSON config file\n"
          "  --output-dir <dir>      override output.dir\n"
          "  --run-seconds <N>       run for N seconds then stop (0 = until signal)\n"
          "  --list-categories       print enabled metric categories and exit\n"
          "  -h, --help              this help\n",
          argv0);
}

void InstallSignals(SignalState& sig) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = [](int s) {
    if (s == SIGHUP) {
      // handled by polling the atomic in RunCollector's ticks; SIGHUP is
      // intentionally non-terminating.
    } else {
      // ignored; termination flag is set below via the real handler.
    }
  };
  // Use a dedicated handler table to keep this simple and async-signal-safe.
  static SignalState* g = nullptr;
  g = &sig;
  struct sigaction sa_stop;
  memset(&sa_stop, 0, sizeof(sa_stop));
  sa_stop.sa_handler = [](int s) {
    if (!g) return;
    if (s == SIGHUP) g->reload.store(true);
    else if (s == SIGUSR1) g->deep_request.store(true);
    else if (s == SIGUSR2) g->base_request.store(true);
    else g->stop.store(true);
  };
  sigaction(SIGHUP, &sa_stop, nullptr);
  sigaction(SIGINT, &sa_stop, nullptr);
  sigaction(SIGTERM, &sa_stop, nullptr);
  sigaction(SIGUSR1, &sa_stop, nullptr);
  sigaction(SIGUSR2, &sa_stop, nullptr);
  (void)sa;
}

}  // namespace

int main(int argc, char** argv) {
  std::string config_path;
  std::string output_dir;
  bool list_categories = false;
  uint64_t run_seconds = 0;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto need_value = [&](const char* flag) -> const char* {
      if (i + 1 >= argc) {
        fprintf(stderr, "error: %s requires a value\n", flag);
        exit(2);
      }
      return argv[++i];
    };
    if (a == "--config") {
      config_path = need_value("--config");
    } else if (a == "--output-dir") {
      output_dir = need_value("--output-dir");
    } else if (a == "--run-seconds") {
      run_seconds = strtoull(need_value("--run-seconds"), nullptr, 10);
    } else if (a == "--list-categories") {
      list_categories = true;
    } else if (a == "-h" || a == "--help") {
      PrintUsage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "error: unknown option '%s'\n", a.c_str());
      PrintUsage(argv[0]);
      return 2;
    }
  }

  Config cfg = DefaultConfig();

  // 1. config file
  if (!config_path.empty()) {
    std::ifstream f(config_path);
    if (!f.good()) {
      fprintf(stderr, "error: cannot open config file '%s'\n", config_path.c_str());
      return 1;
    }
    nlohmann::json j;
    try {
      f >> j;
    } catch (const std::exception& e) {
      fprintf(stderr, "error: config file '%s' is not valid JSON: %s\n", config_path.c_str(), e.what());
      return 1;
    }
    cfg = MergeConfig(cfg, j);
  }

  // 2. environment
  ApplyEnvOverrides(cfg);

  // 3. command line (highest precedence)
  if (!output_dir.empty()) cfg.output.dir = output_dir;

  Sanitize(cfg);

  if (list_categories) {
    for (size_t i = 0; i < cfg.misc.categories.size(); ++i) {
      if (i) printf(" ");
      printf("%s", cfg.misc.categories[i].c_str());
    }
    printf("\n");
    return 0;
  }

  Logger::Instance().Init("", ParseLogLevel(cfg.misc.log_level));

  SignalState sig;
  InstallSignals(sig);

  int rc = RunCollector(cfg, config_path, run_seconds, sig);
  return rc;
}