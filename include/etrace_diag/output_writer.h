#pragma once

#include <memory>
#include <string>

#include <nlohmann/json.hpp>

#include "etrace_diag/config.h"
#include "etrace_diag/metrics.h"

struct sqlite3;
struct sqlite3_stmt;

namespace etrace_diag {

// Persists all collector output into a single SQLite database per session:
//   <output.dir>/<YYYYmmdd-HHMMSS>_<pid>/etrace.sqlite3
// The schema is the unique authoritative DDL (see Init); the web frontend
// (tools/viz) reads the same tables via vendored sql.js.
//
// Threading: the collector writes from a single thread; the logger sink calls
// back into WriteLogLine on that same thread. sqlite busy_timeout(2000) is set
// as a safety net, but there are no concurrent writers.
class OutputWriter {
 public:
  // Creates the session directory and the database (PRAGMA + DDL + meta rows).
  // On failure logs the sqlite error and returns false (caller aborts).
  bool Init(const Config& cfg);
  // WAL checkpoint + close. Any open nested batch is rolled back first.
  void Close();
  const std::string& session_dir() const { return session_dir_; }
  std::string db_path() const { return session_dir_ + "/etrace.sqlite3"; }

  // BASE outputs.
  void WriteHostRow(const HostSnapshot& s, const NetworkSnapshot& net,
                    const GpuSnapshot& gpu, const CgroupSnapshot& cg);
  void WriteAnomalyFeatures(const nlohmann::json& f);    // anomaly + anomaly_tid (from ebpf.*/seq)
  void WriteTargetsEvent(const nlohmann::json& e);       // targets_log: action/tgid/tid/comm/score/rank
  void WriteMemoryEvent(const nlohmann::json& e);        // has "pid" -> oom_events; else memory_events
  void WriteBpfStats(const BpfStatsSnapshot& s);         // bpf_stats (one row per prog)
  void WriteProcOverhead(const ProcOverhead& s);         // proc_overhead
  void WriteLogLine(const std::string& line);            // logs (logger sink; full raw line)

  // DEEP evidence (rows keyed by current deep ordinal).
  bool OpenDeep(int ordinal);                            // INSERT INTO deep_episodes(ordinal)
  void CloseDeep();                                      // ordinal_ = -1
  void WritePreSeries(const CanonicalSnapshot& s);       // deep_series phase=0
  void WritePostSeries(const CanonicalSnapshot& s);      // deep_series phase=1
  void WritePostSeriesGap(uint64_t from_head, uint64_t to_head);  // deep_gap @ last_deep_ts_
  void WriteMeta(const nlohmann::json& meta_json);       // UPDATE deep_episodes SET meta_json
  void WriteSummary(const std::string& content);         // UPDATE deep_episodes SET summary_text
  void WriteFoldedLine(const std::string& kind, const std::string& frames, uint64_t value);
  // id 为系统调用号，name 为对应系统调用名（read/write/open/...，writer 内查表）。
  void WriteDeepSyscall(uint32_t tid, uint32_t id, uint64_t count, float avg_us,
                        float p50_us, float p99_us, uint64_t error_count);
  // sym 为锁地址解析出的内核符号（"name+0x..."，由调用方经 KernelSym 解析）。
  void WriteDeepLock(uint64_t addr, uint64_t count, uint64_t lat_sum, const char* sym);
  void WriteDeepRunq(uint32_t tid, uint64_t count, float avg_us, float p50_us, float p99_us);
  void WriteDeepIoFile(uint32_t dev, uint64_t ino, const char* path, uint64_t bytes,
                       uint32_t ops, uint64_t errors, uint64_t lat_sum, const uint32_t* hist,
                       float p50_us, float p99_us);
  void WriteDeepProcess(const DeepProcessRow& r);        // deep_proc
  void WriteDeepIoDevice(const DeepIoDeviceRow& r);      // deep_io_device
  void WriteDeepNetFlow(const DeepNetFlowRow& r);        // deep_net_flow
  void WriteDeepNetDrop(const DeepNetDropRow& r);        // deep_net_drop
  void WriteDeepNetSoftirq(const DeepNetSoftirqRow& r);  // deep_net_softirq
  void WriteDeepGpuProcess(const DeepGpuProcessRow& r);  // deep_gpu_process
  void WriteDeepOffcpu(const DeepOffcpuRow& r);          // deep_offcpu

  // Nested write batching: BEGIN IMMEDIATE on first BeginBatch, COMMIT on the
  // outermost CommitBatch. Write failures log and continue (observation-grade).
  void BeginBatch();
  void CommitBatch();

 private:
  sqlite3_stmt* Prep(int idx);                       // lazy prepare; SQL table in writer.cpp
  bool Step(int idx, const char* table);             // step-to-DONE, reset, log-on-error
  bool Exec(const char* sql);                        // sqlite3_exec, log-on-error
  void WriteSeries(int phase, const CanonicalSnapshot& s);  // shared deep_series writer

  sqlite3* db_ = nullptr;
  int ordinal_ = -1;               // current deep ordinal (-1 = none)
  uint64_t last_deep_ts_ = 0;      // ts of last written deep_series row
  int batch_depth_ = 0;            // nested transaction depth
  std::string session_dir_;
  std::unique_ptr<sqlite3_stmt*[]> stmts_;  // lazily prepared statement cache
  int stmt_count_ = 0;
};

}  // namespace etrace_diag