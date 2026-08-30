#pragma once

#include <bpf/libbpf.h>

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "collect/map_reader.h"
#include "etrace_diag/metrics.h"

struct etrace_bpf;  // generated skeleton (bpf/etrace.skel.h)

namespace etrace_diag {

// Resolves stack IPs to folded strings. Kernel addresses via /proc/kallsyms;
// user addresses via /proc/<pid>/maps (file+offset; dladdr for own process).
// Each stack_id is resolved once and cached by the caller.
class StackSymbolizer {
 public:
  StackSymbolizer();
  // ips[0..n) are leaf-first; the returned string is root-first (input order reversed), so flame graphs read top-down without client-side flipping. `user` selects user vs kernel resolution.
  std::string Resolve(u32 pid, const uint64_t* ips, int n, bool user);

  // Resolve a kernel address to "name+0xoff" (or hex fallback). Public so DEEP
  // lock-address symbols can be resolved for storage.
  std::string KernelSym(uint64_t ip) const;

 private:
  void LoadKallsyms();
  std::string UserSym(u32 pid, uint64_t ip);

  struct Mapping {
    uint64_t start, end, offset;
    std::string path;
    bool exec;
  };

  std::vector<std::pair<uint64_t, std::string>> ksyms_;       // addr -> name
  std::unordered_map<uint32_t, std::vector<Mapping>> maps_cache_;
};

// Owns the etrace_bpf skeleton: open/load, always-on attach, timer arming,
// map access, target membership edits, and the iter/task process table.
class EbpfManager {
 public:
  ~EbpfManager();

  bool Load();   // open + load + attach always-on programs
  void Close();

  struct etrace_bpf* skel() { return skel_; }
  struct bpf_map* Map(const char* name);
  MapSlice* Slice(const char* name);

  bool SetDeep(bool on);
  bool WriteSnapshotCfg(uint32_t interval_ms);
  bool WriteSampleRateCfg(uint32_t offcpu_rate, uint32_t iofile_rate);
  bool WriteNcpus(int n);
  bool ArmTimer(uint64_t interval_ms, bool cancel);

  // Recorder producer control, mode-agnostic:
  //  - >= 6.4: bpf_timer (ArmTimer / snapshot_cfg)
  //  - < 6.4:  per-CPU PERF_COUNT_SW_CPU_CLOCK sampler (perf_event_open)
  bool StartSnapshotter(uint64_t interval_ms);
  bool SetSnapshotInterval(uint64_t interval_ms);
  void StopSnapshotter();
  // true => the host must merge per-CPU records into summed snapshots.
  static bool RecorderPerCpu();

  bool AddTarget(uint32_t tid, uint32_t flags, uint32_t tgid, const char* comm);
  bool RemoveTarget(uint32_t tid);

  bool ReadProcessTable(std::vector<ProcessRow>& out);

  // Per-program run_cnt/run_time_ns via BPF_OBJ_GET_INFO_BY_FD.
  // Returns non-zero run_time_ns only when kernel.bpf_stats_enabled==1.
  bool CollectProgramStats(std::vector<BpfProgStats>& out);

  struct bpf_program* Prog(const char* name);
  StackSymbolizer& sym() { return sym_; }

 private:
  bool AttachAlwaysOn();
  bool Attach(struct bpf_program* p);
  bool OpenRecorderPerf(uint64_t interval_ms);
  void CloseRecorderPerf();

  struct etrace_bpf* skel_ = nullptr;
  std::vector<struct bpf_link*> links_;
  std::vector<int> recorder_fds_;
  std::unordered_map<std::string, std::unique_ptr<MapSlice>> slices_;
  StackSymbolizer sym_;
};

}  // namespace etrace_diag