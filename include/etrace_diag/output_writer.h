#pragma once

#include <fstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "etrace_diag/config.h"
#include "etrace_diag/metrics.h"

namespace etrace_diag {

// Writes all text outputs under a per-run session directory:
//   <output.dir>/<YYYYmmdd-HHMMSS>_<pid>/
// Metrics use JSON Lines ("v":1); profiles use flamegraph folded format.
class OutputWriter {
 public:
  // Creates the session directory and opens the base files. Returns false on
  // any filesystem error.
  bool Init(const Config& cfg);

  const std::string& session_dir() const { return session_dir_; }
  const std::string& deep_dir() const { return deep_dir_; }

  // BASE outputs (one JSON object per line).
  void WriteHostRow(const HostSnapshot& s);                              // base_host.jsonl
  void WriteAnomalyFeatures(const nlohmann::json& f);                    // base_anomaly.jsonl
  void WriteTargetsEvent(const nlohmann::json& e);                       // targets.log
  void WriteMemoryEvent(const nlohmann::json& e);                        // memory_events.txt
  void WriteIoDevice(const nlohmann::json& e);                           // io_devices.txt
  void WriteBpfStats(const BpfStatsSnapshot& s);                         // bpf_stats.jsonl
  void WriteProcOverhead(const ProcOverhead& s);                         // proc_overhead.jsonl

  // DEEP directory lifecycle.
  bool OpenDeep(int ordinal);        // deep/<N>/ + meta.json + series files
  void CloseDeep();
  void WritePreSeries(const CanonicalSnapshot& s);
  void WritePostSeries(const CanonicalSnapshot& s);
  void WritePostSeriesGap(uint64_t from_head, uint64_t to_head);
  void WriteHostSeries(const HostSnapshot& s);

  // Folded profile / hotspot text emissions into the current deep dir.
  void WriteFolded(const std::string& filename, const std::string& content);
  void WriteText(const std::string& filename, const std::string& content);
  void WriteSummary(const std::string& content);
  void WriteMeta(const nlohmann::json& meta_json);

  // Utility: format a monotonic timestamp (ns) as an ISO-ish string.
  static std::string IsoNs(uint64_t ts_ns);

 private:
  bool Append(const std::string& path, const std::string& line);
  bool OpenAppend(std::ofstream& os, const std::string& path);

  std::string session_dir_;
  std::string deep_dir_;

  std::ofstream host_f_;
  std::ofstream anomaly_f_;
  std::ofstream targets_f_;
  std::ofstream memory_f_;
  std::ofstream io_f_;
  std::ofstream bpf_stats_f_;
  std::ofstream proc_f_;

  std::ofstream pre_f_;
  std::ofstream post_f_;
  std::ofstream hostseries_f_;
};

}  // namespace etrace_diag