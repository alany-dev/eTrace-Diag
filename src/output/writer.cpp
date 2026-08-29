#include "etrace_diag/output_writer.h"

#include <ctime>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace etrace_diag {

namespace {
std::string NowDirName() {
  time_t t = time(nullptr);
  struct tm tmv;
  localtime_r(&t, &tmv);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y%m%d-%H%M%S", &tmv);
  return buf;
}
}  // namespace

std::string OutputWriter::IsoNs(uint64_t ts_ns) {
  // Monotonic ns -> wallclock ISO string is not meaningful; render as
  // "<seconds>.<9-digit-nanos>" relative to the CLOCK_MONOTONIC origin. This is
  // stable within a run and sufficient for cross-referencing records.
  char buf[64];
  uint64_t sec = ts_ns / 1000000000ULL;
  uint64_t ns = ts_ns % 1000000000ULL;
  snprintf(buf, sizeof(buf), "%llu.%09llu", (unsigned long long)sec, (unsigned long long)ns);
  return buf;
}

bool OutputWriter::Append(const std::string& path, const std::string& line) {
  std::ofstream f(path, std::ios::app);
  if (!f.good()) return false;
  f << line << "\n";
  return f.good();
}

bool OutputWriter::OpenAppend(std::ofstream& os, const std::string& path) {
  os.open(path, std::ios::app);
  return os.good();
}

bool OutputWriter::Init(const Config& cfg) {
  std::string base = cfg.output.dir;
  if (base.empty()) base = "out";
  session_dir_ = base + "/" + NowDirName() + "_" + std::to_string(getpid());

  if (mkdir(cfg.output.dir.c_str(), 0755) != 0 && errno != EEXIST) return false;
  if (mkdir(session_dir_.c_str(), 0755) != 0) return false;

  if (!OpenAppend(host_f_, session_dir_ + "/base_host.jsonl")) return false;
  if (!OpenAppend(anomaly_f_, session_dir_ + "/base_anomaly.jsonl")) return false;
  if (!OpenAppend(targets_f_, session_dir_ + "/targets.log")) return false;
  if (!OpenAppend(memory_f_, session_dir_ + "/memory_events.txt")) return false;
  if (!OpenAppend(io_f_, session_dir_ + "/io_devices.txt")) return false;
  if (!OpenAppend(bpf_stats_f_, session_dir_ + "/bpf_stats.jsonl")) return false;
  if (!OpenAppend(proc_f_, session_dir_ + "/proc_overhead.jsonl")) return false;
  return true;
}

void OutputWriter::WriteHostRow(const HostSnapshot& s) {
  nlohmann::json j;
  to_json(j, s);
  host_f_ << j.dump() << "\n";
  host_f_.flush();
}

void OutputWriter::WriteAnomalyFeatures(const nlohmann::json& f) {
  anomaly_f_ << f.dump() << "\n";
  anomaly_f_.flush();
}

void OutputWriter::WriteTargetsEvent(const nlohmann::json& e) {
  targets_f_ << e.dump() << "\n";
  targets_f_.flush();
}

void OutputWriter::WriteMemoryEvent(const nlohmann::json& e) {
  memory_f_ << e.dump() << "\n";
  memory_f_.flush();
}

void OutputWriter::WriteIoDevice(const nlohmann::json& e) {
  io_f_ << e.dump() << "\n";
  io_f_.flush();
}

void OutputWriter::WriteBpfStats(const BpfStatsSnapshot& s) {
  nlohmann::json j;
  to_json(j, s);
  bpf_stats_f_ << j.dump() << "\n";
  bpf_stats_f_.flush();
}

void OutputWriter::WriteProcOverhead(const ProcOverhead& s) {
  nlohmann::json j;
  to_json(j, s);
  proc_f_ << j.dump() << "\n";
  proc_f_.flush();
}

bool OutputWriter::OpenDeep(int ordinal) {
  deep_dir_ = session_dir_ + "/deep/" + std::to_string(ordinal);
  std::string parent = session_dir_ + "/deep";
  if (mkdir(parent.c_str(), 0755) != 0 && errno != EEXIST) return false;
  if (mkdir(deep_dir_.c_str(), 0755) != 0) return false;

  if (!OpenAppend(pre_f_, deep_dir_ + "/pre_series.jsonl")) return false;
  if (!OpenAppend(post_f_, deep_dir_ + "/post_series.jsonl")) return false;
  if (!OpenAppend(hostseries_f_, deep_dir_ + "/host_series.jsonl")) return false;
  return true;
}

void OutputWriter::CloseDeep() {
  pre_f_.close();
  post_f_.close();
  hostseries_f_.close();
}

void OutputWriter::WritePreSeries(const CanonicalSnapshot& s) {
  nlohmann::json j;
  to_json(j, s);
  pre_f_ << j.dump() << "\n";
}

void OutputWriter::WritePostSeries(const CanonicalSnapshot& s) {
  nlohmann::json j;
  to_json(j, s);
  post_f_ << j.dump() << "\n";
}

void OutputWriter::WritePostSeriesGap(uint64_t from_head, uint64_t to_head) {
  nlohmann::json j = {{"v", 1}, {"post_series_gap", true},
                      {"from_head", from_head}, {"to_head", to_head}};
  post_f_ << j.dump() << "\n";
}

void OutputWriter::WriteHostSeries(const HostSnapshot& s) {
  nlohmann::json j;
  to_json(j, s);
  hostseries_f_ << j.dump() << "\n";
}

void OutputWriter::WriteFolded(const std::string& filename, const std::string& content) {
  Append(deep_dir_ + "/" + filename, content);
}

void OutputWriter::WriteText(const std::string& filename, const std::string& content) {
  Append(deep_dir_ + "/" + filename, content);
}

void OutputWriter::WriteSummary(const std::string& content) {
  Append(deep_dir_ + "/summary.txt", content);
}

void OutputWriter::WriteMeta(const nlohmann::json& meta_json) {
  std::ofstream f(deep_dir_ + "/meta.json");
  if (f.good()) f << meta_json.dump(2) << "\n";
}

}  // namespace etrace_diag