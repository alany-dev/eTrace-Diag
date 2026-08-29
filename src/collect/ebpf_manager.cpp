#include "collect/ebpf_manager.h"

#include <bpf/bpf.h>
#include <dlfcn.h>

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>

#include "etrace.skel.h"
#include "logging.h"

namespace etrace_diag {

// ---------------------------------------------------------------------------
// StackSymbolizer
// ---------------------------------------------------------------------------
StackSymbolizer::StackSymbolizer() { LoadKallsyms(); }

void StackSymbolizer::LoadKallsyms() {
  ksyms_.clear();
  std::ifstream f("/proc/kallsyms");
  std::string line;
  while (std::getline(f, line)) {
    std::istringstream is(line);
    uint64_t addr = 0;
    char type = 0;
    std::string name;
    if (is >> std::hex >> addr >> type >> name) {
      // Skip module symbol table entries (keep both; module names are usable).
      if (name.empty()) continue;
      ksyms_.push_back({addr, std::move(name)});
    }
  }
}

std::string StackSymbolizer::KernelSym(uint64_t ip) const {
  if (ksyms_.empty()) return "<kernel>";
  // binary search for greatest addr <= ip
  size_t lo = 0, hi = ksyms_.size();
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (ksyms_[mid].first <= ip) lo = mid + 1;
    else hi = mid;
  }
  if (lo == 0) {  // ip below first symbol
    char buf[32];
    snprintf(buf, sizeof(buf), "%llx", (unsigned long long)ip);
    return buf;
  }
  const auto& hit = ksyms_[lo - 1];
  uint64_t off = ip - hit.first;
  if (off) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s+0x%llx", hit.second.c_str(), (unsigned long long)off);
    return buf;
  }
  return hit.second;
}

std::string StackSymbolizer::UserSym(u32 pid, uint64_t ip) {
  // Own process: dladdr can give a real symbol name.
  if (pid == (u32)getpid()) {
    Dl_info info;
    if (dladdr((void*)ip, &info) && info.dli_sname) {
      return info.dli_sname;
    }
  }

  auto it = maps_cache_.find(pid);
  if (it == maps_cache_.end()) {
    std::string path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream f(path);
    std::string line;
    std::vector<Mapping> maps;
    while (std::getline(f, line)) {
      std::istringstream is(line);
      uint64_t start = 0, end = 0, offset = 0;
      char dash = 0, perms[5] = {0};
      std::string rest;
      is >> std::hex >> start >> dash >> end;
      if (dash != '-') break;
      is >> perms >> std::hex >> offset;
      std::getline(is, rest);
      // trailing path
      size_t pos = rest.find_first_not_of(' ');
      std::string mp = (pos == std::string::npos) ? "" : rest.substr(pos);
      if (mp.empty()) mp = "[anon]";
      bool exec = perms[2] == 'x';
      maps.push_back({start, end, offset, std::move(mp), exec});
    }
    it = maps_cache_.emplace(pid, std::move(maps)).first;
  }

  for (const auto& m : it->second) {
    if (ip >= m.start && ip < m.end) {
      uint64_t off = (ip - m.start) + m.offset;
      char buf[512];
      snprintf(buf, sizeof(buf), "%s+0x%llx", m.path.c_str(), (unsigned long long)off);
      return buf;
    }
  }
  char buf[32];
  snprintf(buf, sizeof(buf), "%llx", (unsigned long long)ip);
  return buf;
}

std::string StackSymbolizer::Resolve(u32 pid, const uint64_t* ips, int n, bool user) {
  std::string out;
  for (int i = 0; i < n; ++i) {
    if (ips[i] == 0) break;
    if (!out.empty()) out += ";";
    std::string sym = user ? UserSym(pid, ips[i]) : KernelSym(ips[i]);
    // sanitize: folded frames must not contain ';' or spaces
    for (auto& c : sym)
      if (c == ';' || c == ' ' || c == '\t') c = '_';
    out += sym;
  }
  return out;
}

// ---------------------------------------------------------------------------
// EbpfManager
// ---------------------------------------------------------------------------
EbpfManager::~EbpfManager() { Close(); }

void EbpfManager::Close() {
  CloseRecorderPerf();
  for (auto* l : links_) bpf_link__destroy(l);
  links_.clear();
  if (skel_) {
    etrace_bpf__destroy(skel_);
    skel_ = nullptr;
  }
}

struct bpf_program* EbpfManager::Prog(const char* name) {
  if (!skel_) return nullptr;
  struct bpf_program* p = bpf_object__find_program_by_name(skel_->obj, name);
  return p;
}

bool EbpfManager::Attach(struct bpf_program* p) {
  if (!p) return false;
  struct bpf_link* l = bpf_program__attach(p);
  if (!l) {
    LogError("attach %s: %s", bpf_program__name(p), strerror(errno));
    return false;
  }
  links_.push_back(l);
  return true;
}

bool EbpfManager::AttachAlwaysOn() {
  const char* names[] = {
      "on_switch", "on_wakeup", "on_wakeup_new",
      "on_rq_insert", "on_rq_issue", "on_rq_complete",
      "fault_ret",
      "on_kswapd_wake", "on_kswapd_sleep",
      "on_direct_reclaim_begin", "on_direct_reclaim_end",
      "on_mark_victim",
#ifdef ETD_HAVE_LOCK_CONTENTION_TP
      "on_contention_begin", "on_contention_end",
#else
      "mutex_lock_slow", "mutex_lock_slow_ret",
#endif
  };
  for (const char* n : names) {
    if (!Attach(Prog(n))) return false;
  }
  return true;
}

bool EbpfManager::Load() {
  skel_ = etrace_bpf__open();
  if (!skel_) {
    LogError("etrace_bpf__open: %s", strerror(errno));
    return false;
  }

  int err = etrace_bpf__load(skel_);
  if (err) {
    LogError("etrace_bpf__load: %s (kernel >=6.6 with CONFIG_DEBUG_INFO_BTF required; "
             "CO-RE load will fail-fast without it)", strerror(-err));
    etrace_bpf__destroy(skel_);
    skel_ = nullptr;
    return false;
  }

  // Frozen-layout guard: recorder value size must equal our mirror struct.
  struct bpf_map* rec = Map("recorder");
  if (!rec || bpf_map__value_size(rec) != sizeof(KernelSnapshotRec)) {
    LogError("recorder map value size mismatch (kernel=%zu host=%zu); layout contract broken",
             rec ? (size_t)bpf_map__value_size(rec) : (size_t)0, sizeof(KernelSnapshotRec));
    Close();
    return false;
  }

  if (!AttachAlwaysOn()) {
    Close();
    return false;
  }
  return true;
}

struct bpf_map* EbpfManager::Map(const char* name) {
  if (!skel_) return nullptr;
  return bpf_object__find_map_by_name(skel_->obj, name);
}

MapSlice* EbpfManager::Slice(const char* name) {
  auto it = slices_.find(name);
  if (it != slices_.end()) return it->second.get();
  struct bpf_map* m = Map(name);
  auto s = std::make_unique<MapSlice>(m);
  MapSlice* raw = s.get();
  slices_.emplace(name, std::move(s));
  return raw;
}

bool EbpfManager::SetDeep(bool on) {
  u32 key = 0, val = on ? 1 : 0;
  return bpf_map_update_elem(bpf_map__fd(Map("deep_enabled")), &key, &val, BPF_ANY) == 0;
}

bool EbpfManager::WriteSnapshotCfg(u32 interval_ms) {
  u32 key = 0;
  return bpf_map_update_elem(bpf_map__fd(Map("snapshot_cfg")), &key, &interval_ms, BPF_ANY) == 0;
}

bool EbpfManager::WriteSampleRateCfg(u32 offcpu, u32 iofile) {
  u32 key = 0;
  u32 thresh = iofile ? (u32)(0xFFFFFFFFULL / iofile) : 0;
  struct { u32 offcpu; u32 iofile_thresh; } v = {offcpu, thresh};
  return bpf_map_update_elem(bpf_map__fd(Map("sample_rate_cfg")), &key, &v, BPF_ANY) == 0;
}

bool EbpfManager::ArmTimer(u64 interval_ms, bool cancel) {
  struct arm_cmd_val { u64 interval_ns; u64 cancel; };
  u32 key = 0;
  arm_cmd_val cmd = {interval_ms * 1000000ULL, cancel ? 1ULL : 0ULL};
  struct bpf_map* m = Map("arm_cmd");
  if (!m || bpf_map_update_elem(bpf_map__fd(m), &key, &cmd, BPF_ANY) != 0) return false;

  struct bpf_program* p = Prog("arm_snapshotter");
  if (!p) return false;
  int fd = bpf_program__fd(p);
  if (fd < 0) return false;

  struct bpf_test_run_opts opts = {};
  opts.sz = sizeof(opts);
  opts.repeat = 1;
  int err = bpf_prog_test_run_opts(fd, &opts);
  if (err && errno) LogWarn("arm_snapshotter test_run: %s", strerror(errno));
  return err == 0;
}

bool EbpfManager::WriteNcpus(int n) {
  u32 key = 0;
  u32 v = (u32)(n > 0 ? n : 1);
  return bpf_map_update_elem(bpf_map__fd(Map("ncpus")), &key, &v, BPF_ANY) == 0;
}

bool EbpfManager::RecorderPerCpu() {
#ifdef ETD_HAVE_PERCPU_LOOKUP_ELEM
  return false;  // summed (timer) mode
#else
  return true;   // per-CPU perf sampler mode
#endif
}

bool EbpfManager::OpenRecorderPerf(uint64_t interval_ms) {
  struct bpf_program* p = Prog("snapshotter");
  if (!p) return false;
  int prog_fd = bpf_program__fd(p);
  if (prog_fd < 0) return false;

  struct perf_event_attr attr = {};
  attr.type = PERF_TYPE_SOFTWARE;
  attr.size = sizeof(attr);
  attr.config = PERF_COUNT_SW_CPU_CLOCK;
  attr.sample_period = interval_ms * 1000000ULL;
  attr.wakeup_events = 1;

  int ncpus = libbpf_num_possible_cpus();
  for (int cpu = 0; cpu < ncpus; ++cpu) {
    int pfd = (int)syscall(__NR_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (pfd < 0) {
      CloseRecorderPerf();
      return false;
    }
    ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd);
    ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
    recorder_fds_.push_back(pfd);
  }
  return true;
}

void EbpfManager::CloseRecorderPerf() {
  for (int fd : recorder_fds_) close(fd);
  recorder_fds_.clear();
}

bool EbpfManager::StartSnapshotter(uint64_t interval_ms) {
#ifdef ETD_HAVE_PERCPU_LOOKUP_ELEM
  if (!WriteSnapshotCfg((u32)interval_ms)) return false;
  return ArmTimer(interval_ms, false);
#else
  if (!WriteSnapshotCfg((u32)interval_ms)) return false;  // map unused in this mode, harmless
  return OpenRecorderPerf(interval_ms);
#endif
}

bool EbpfManager::SetSnapshotInterval(uint64_t interval_ms) {
#ifdef ETD_HAVE_PERCPU_LOOKUP_ELEM
  return WriteSnapshotCfg((u32)interval_ms);  // snap_tick re-reads each tick
#else
  u64 period = interval_ms * 1000000ULL;
  for (int fd : recorder_fds_) ioctl(fd, PERF_EVENT_IOC_PERIOD, &period);
  return !recorder_fds_.empty();
#endif
}

void EbpfManager::StopSnapshotter() {
#ifdef ETD_HAVE_PERCPU_LOOKUP_ELEM
  ArmTimer(0, true);
#else
  CloseRecorderPerf();
#endif
}

bool EbpfManager::AddTarget(u32 tid, u32 flags, u32 tgid, const char* comm) {
  struct bpf_map* t = Map("targets");
  if (!t || bpf_map_update_elem(bpf_map__fd(t), &tid, &flags, BPF_ANY) != 0) return false;
  struct task_meta_t { u32 tgid; u8 comm[16]; };
  struct bpf_map* tm = Map("task_meta");
  if (tm) {
    task_meta_t meta = {};
    meta.tgid = tgid;
    if (comm) {
      strncpy((char*)meta.comm, comm, 15);
      meta.comm[15] = 0;
    }
    bpf_map_update_elem(bpf_map__fd(tm), &tid, &meta, BPF_ANY);
  }
  return true;
}

bool EbpfManager::RemoveTarget(u32 tid) {
  if (bpf_map_delete_elem(bpf_map__fd(Map("targets")), &tid) != 0 && errno != ENOENT)
    return false;
  struct bpf_map* tm = Map("task_meta");
  if (tm) bpf_map_delete_elem(bpf_map__fd(tm), &tid);
  return true;
}

bool EbpfManager::ReadProcessTable(std::vector<ProcessRow>& out) {
  out.clear();
  struct bpf_program* p = Prog("task_iter");
  if (!p) return false;
  struct bpf_link* link = bpf_program__attach_iter(p, nullptr);
  if (!link) return false;
  int it_fd = bpf_iter_create(bpf_link__fd(link));
  if (it_fd < 0) {
    bpf_link__destroy(link);
    return false;
  }

  char buf[8192];
  std::string leftover;
  for (;;) {
    ssize_t n = read(it_fd, buf, sizeof(buf) - 1);
    if (n <= 0) break;
    buf[n] = 0;
    leftover += buf;
    size_t pos = 0;
    while ((pos = leftover.find('\n')) != std::string::npos) {
      std::string line = leftover.substr(0, pos);
      leftover.erase(0, pos + 1);
      ProcessRow r;
      char comm[16] = {0};
      if (sscanf(line.c_str(), "%u %u %15s %hhu %llu %llu %llu %llu %llu %llu",
                 &r.pid, &r.tgid, comm, &r.state,
                 (unsigned long long*)&r.start_time,
                 (unsigned long long*)&r.utime, (unsigned long long*)&r.stime,
                 (unsigned long long*)&r.nvcsw, (unsigned long long*)&r.nivcsw,
                 (unsigned long long*)&r.total_vm) == 10) {
        strncpy(r.comm, comm, 15);
        r.comm[15] = 0;
        out.push_back(r);
      }
    }
  }
  close(it_fd);
  bpf_link__destroy(link);
  return !out.empty();
}

bool EbpfManager::CollectProgramStats(std::vector<BpfProgStats>& out) {
  out.clear();
  if (!skel_) return false;
  struct bpf_object* obj = skel_->obj;
  struct bpf_program* p = nullptr;
  while ((p = bpf_object__next_program(obj, p)) != nullptr) {
    int fd = bpf_program__fd(p);
    if (fd < 0) continue;
    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    if (bpf_prog_get_info_by_fd(fd, &info, &len)) continue;
    BpfProgStats s;
    const char* name = bpf_program__name(p);
    s.name = name ? name : "";
    s.id = info.id;
    s.run_cnt = info.run_cnt;
    s.run_time_ns = info.run_time_ns;
    out.push_back(std::move(s));
  }
  return !out.empty();
}

}  // namespace etrace_diag