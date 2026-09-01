#include "collect/host_metrics.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <time.h>

namespace etrace_diag {

namespace {

uint64_t NowNs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec);
}

std::string ReadFile(const std::string& path) {
  std::ifstream f(path);
  if (!f.good()) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Parses a /proc/stat cpu line:
// "cpuN  user nice system idle iowait irq softirq steal [guest guest_nice] ..."
// guest/guest_nice are optional (absent on kernels without virt accounting).
bool ParseCpuLine(const std::string& line, CpuStat& out) {
  std::istringstream is(line);
  std::string label;
  is >> label;
  if (label.rfind("cpu", 0) != 0) return false;
  if (!(is >> out.user >> out.nice >> out.system >> out.idle >> out.iowait >> out.irq >>
        out.softirq >> out.steal))
    return false;
  // guest/guest_nice are the 9th/10th fields; missing -> stay 0 (not "invalid":
  // their absence means no virt time was ever accounted).
  is >> out.guest >> out.guest_nice;
  return true;
}

// key -> kB value from /proc/meminfo.
bool MeminfoValue(const std::string& text, const char* key, uint64_t& out) {
  size_t pos = text.find(key);
  if (pos == std::string::npos) return false;
  size_t colon = text.find(':', pos);
  if (colon == std::string::npos) return false;
  unsigned long long v = 0;
  if (sscanf(text.c_str() + colon + 1, "%llu", &v) != 1) return false;
  out = static_cast<uint64_t>(v);
  return true;
}

// line-anchored vmstat lookup: returns value or false when key absent.
bool VmstatValue(const std::string& text, const char* key, long long& out) {
  size_t pos = 0;
  size_t klen = strlen(key);
  while ((pos = text.find(key, pos)) != std::string::npos) {
    size_t ws = pos + klen;
    // ensure token boundary
    if (pos == 0 || text[pos - 1] == '\n') {
      long long v = 0;
      if (sscanf(text.c_str() + ws, "%lld", &v) == 1) {
        out = v;
        return true;
      }
    }
    pos += klen;
  }
  return false;
}

// Parses one /proc/pressure/<kind> file LINE BY LINE: "some ..." and
// "full ..." independently. A missing line clears its valid flag rather than
// fabricating zero (CPU pressure usually has no full line).
PsiWindow ParsePsi(const std::string& text) {
  PsiWindow w;
  std::istringstream is(text);
  std::string line;
  while (std::getline(is, line)) {
    PsiWindow* dst = nullptr;
    if (line.rfind("some ", 0) == 0) dst = &w;
    else if (line.rfind("full ", 0) == 0) dst = &w;
    else continue;
    bool is_some = line.rfind("some ", 0) == 0;
    auto readv = [&](const char* k) -> double {
      size_t p = line.find(k);
      if (p == std::string::npos) return 0.0;
      double v = 0;
      if (sscanf(line.c_str() + p + strlen(k), "%lf", &v) == 1) return v;
      return 0.0;
    };
    if (is_some) {
      w.avg10 = readv("avg10=");
      w.avg60 = readv("avg60=");
      w.avg300 = readv("avg300=");
      w.some_valid = true;
    } else {
      w.avg10 = readv("avg10=");
      w.avg60 = readv("avg60=");
      w.avg300 = readv("avg300=");
      w.full_valid = true;
    }
    (void)dst;
  }
  return w;
}

// --- cgroup v2 (collector's own cgroup) ---

struct CgroupLoc {
  std::string root;    // unified cgroup v2 mount point ("" = none)
  std::string path;    // collector cgroup relative path ("" = root cgroup)
};

// Parse /proc/self/cgroup for the unified "0::/path" line, then
// /proc/self/mountinfo for the cgroup2 mount root (5th field = mountpoint).
CgroupLoc FindCgroup() {
  CgroupLoc loc;
  {
    std::istringstream is(ReadFile("/proc/self/cgroup"));
    std::string line;
    while (std::getline(is, line)) {
      if (line.rfind("0::", 0) == 0) {
        loc.path = line.substr(3);
        break;
      }
    }
  }
  {
    std::istringstream is(ReadFile("/proc/self/mountinfo"));
    std::string line;
    while (std::getline(is, line)) {
      // <id> <parent> <maj:min> <root> <mountpoint> <opts> - <fstype> <source> <superopts>
      size_t sep = line.find(" - ");
      if (sep == std::string::npos) continue;
      std::string fs = line.substr(sep + 3);
      if (fs.rfind("cgroup2 ", 0) != 0 && fs.rfind("cgroup2\t", 0) != 0) continue;
      std::istringstream fs_is(fs);
      std::string fstype, src, mnt;
      fs_is >> fstype >> src >> mnt;
      if (fstype != "cgroup2") continue;
      std::istringstream ls(line.substr(0, sep));
      std::string f;
      for (int i = 0; i < 5; ++i) {
        if (!(ls >> f)) { f.clear(); break; }
      }
      loc.root = f;
      break;
    }
  }
  return loc;
}

// numeric value of "<key> <v>" line in a file; returns false when absent.
bool ReadStatU64(const std::string& text, const char* key, uint64_t& out) {
  std::istringstream is(text);
  std::string k;
  while (is >> k) {
    if (k == key) {
      unsigned long long v = 0;
      if (is >> v) {
        out = v;
        return true;
      }
      return false;
    }
  }
  return false;
}

}  // namespace

HostSnapshot HostMetrics::Snapshot() {
  HostSnapshot s;
  s.ts_ns = NowNs();

  // /proc/stat — per-cpu + aggregate + system-wide counters
  std::string stat = ReadFile("/proc/stat");
  {
    std::istringstream is(stat);
    std::string line;
    while (std::getline(is, line)) {
      if (line.rfind("cpu ", 0) == 0) {
        CpuStat t;
        std::istringstream ls(line);
        std::string label;
        ls >> label;
        if (ls >> t.user >> t.nice >> t.system >> t.idle >> t.iowait >> t.irq >> t.softirq >>
            t.steal)
          s.total = t;
        ls >> s.total.guest >> s.total.guest_nice;  // optional
      } else if (line.rfind("cpu", 0) == 0) {
        CpuStat c;
        if (ParseCpuLine(line, c)) s.cpus.push_back(c);
      } else if (line.rfind("ctxt ", 0) == 0) {
        sscanf(line.c_str() + 5, "%llu", (unsigned long long*)&s.ctxt);
      } else if (line.rfind("processes ", 0) == 0) {
        sscanf(line.c_str() + 10, "%llu", (unsigned long long*)&s.processes);
      } else if (line.rfind("procs_running ", 0) == 0) {
        sscanf(line.c_str() + 14, "%llu", (unsigned long long*)&s.procs_running);
      } else if (line.rfind("procs_blocked ", 0) == 0) {
        sscanf(line.c_str() + 14, "%llu", (unsigned long long*)&s.procs_blocked);
      }
    }
  }

  // /proc/loadavg — loads + run-queue length (4th token "running/threads")
  {
    std::string la = ReadFile("/proc/loadavg");
    unsigned long running = 0, threads = 0;
    if (sscanf(la.c_str(), "%lf %lf %lf %lu/%lu", &s.load.load1, &s.load.load5, &s.load.load15,
               &running, &threads) == 5) {
      s.load.nr_running = static_cast<uint32_t>(running);
      s.load.nr_threads = static_cast<uint32_t>(threads);
    }
  }

  // /proc/meminfo (valid_mask bits fixed in metrics.h)
  {
    std::string mi = ReadFile("/proc/meminfo");
    auto get = [&](const char* key, uint64_t& out, uint32_t bit) {
      if (MeminfoValue(mi, key, out)) s.mem.valid_mask |= (1u << bit);
    };
    get("MemTotal", s.mem.mem_total_kb, 0);
    get("MemAvailable", s.mem.mem_available_kb, 1);
    get("MemFree", s.mem.mem_free_kb, 2);
    get("Buffers", s.mem.buffers_kb, 3);
    get("Cached", s.mem.cached_kb, 4);
    get("SwapTotal", s.mem.swap_total_kb, 5);
    get("SwapFree", s.mem.swap_free_kb, 6);
    get("AnonPages", s.mem.anon_pages_kb, 7);
    get("SReclaimable", s.mem.sreclaimable_kb, 8);
    get("Shmem", s.mem.shmem_kb, 9);
    get("Dirty", s.mem.dirty_kb, 10);
    get("Writeback", s.mem.writeback_kb, 11);
    get("CommitLimit", s.mem.commit_limit_kb, 12);
    get("Committed_AS", s.mem.committed_as_kb, 13);
  }

  // /proc/vmstat (nr_free_pages / nr_anon_pages intentionally not exported)
  {
    std::string vs = ReadFile("/proc/vmstat");
    long long v = 0;
    auto get = [&](const char* key, uint64_t& out, uint32_t bit) {
      if (VmstatValue(vs, key, v)) {
        out = static_cast<uint64_t>(v > 0 ? v : 0);
        s.vm.valid_mask |= (1u << bit);
      }
    };
    get("pgfault", s.vm.pgfault, 0);
    get("pgmajfault", s.vm.pgmajfault, 1);
    get("pswpin", s.vm.pswpin, 2);
    get("pswpout", s.vm.pswpout, 3);
    get("pgscan_kswapd", s.vm.pgscan_kswapd, 4);
    get("pgscan_direct", s.vm.pgscan_direct, 5);
    get("pgsteal_kswapd", s.vm.pgsteal_kswapd, 6);
    get("pgsteal_direct", s.vm.pgsteal_direct, 7);
    get("workingset_refault", s.vm.workingset_refault, 8);
    get("nr_dirty", s.vm.nr_dirty, 9);
    get("nr_writeback", s.vm.nr_writeback, 10);
  }

  // /proc/pressure/{cpu,io,memory} — two-level PSI, per-line parsing
  {
    s.psi.cpu = ParsePsi(ReadFile("/proc/pressure/cpu"));
    s.psi.io = ParsePsi(ReadFile("/proc/pressure/io"));
    s.psi.memory = ParsePsi(ReadFile("/proc/pressure/memory"));
  }

  // /proc/diskstats — per-device cumulative counters. Kernel 4.18+ layout
  // (after major/minor/name): reads_completed reads_merged sectors_read
  // read_ticks_ms writes_completed writes_merged sectors_written write_ticks_ms
  // ios_in_flight io_ticks_ms weighted_ticks_ms. Each parsed field sets its
  // fixed presence bit; shorter lines (older kernels) simply lack the tail
  // bits.
  {
    std::istringstream is(ReadFile("/proc/diskstats"));
    std::string line;
    while (std::getline(is, line)) {
      if (line.empty()) continue;
      std::istringstream ls(line);
      DiskStatRow d;
      std::string name;
      if (!(ls >> d.major >> d.minor >> name)) continue;
      snprintf(d.name, sizeof(d.name), "%s", name.c_str());
      if (ls >> d.reads_completed) d.valid_mask |= 1u << 0;
      if (ls >> d.reads_merged) d.valid_mask |= 1u << 1;
      if (ls >> d.sectors_read) d.valid_mask |= 1u << 2;
      if (ls >> d.read_ticks_ms) d.valid_mask |= 1u << 3;
      if (ls >> d.writes_completed) d.valid_mask |= 1u << 4;
      if (ls >> d.writes_merged) d.valid_mask |= 1u << 5;
      if (ls >> d.sectors_written) d.valid_mask |= 1u << 6;
      if (ls >> d.write_ticks_ms) d.valid_mask |= 1u << 7;
      if (ls >> d.ios_in_flight) d.valid_mask |= 1u << 8;
      if (ls >> d.io_ticks_ms) d.valid_mask |= 1u << 9;
      if (ls >> d.weighted_ticks_ms) d.valid_mask |= 1u << 10;
      // A row with only the first three tokens parsed is meaningless; require
      // at least the core throughput fields.
      if ((d.valid_mask & ((1u << 0) | (1u << 4))) == 0) continue;
      s.disks.push_back(d);
    }
  }

  return s;
}

CgroupSnapshot HostMetrics::ReadCgroup(uint64_t ts_ns) {
  CgroupSnapshot s;
  s.ts_ns = ts_ns;
  CgroupLoc loc = FindCgroup();
  if (loc.root.empty()) {
    s.available = false;
    s.error = "no unified cgroup v2 mount";
    return s;
  }
  std::string base = loc.root;
  if (!loc.path.empty()) base += loc.path;
  s.cgroup_path = base;
  s.available = true;

  // cpu.stat
  {
    std::string txt = ReadFile(base + "/cpu.stat");
    uint64_t v = 0;
    bool any = false;
    if (ReadStatU64(txt, "usage_usec", v)) { s.cpu_usage_usec = v; any = true; }
    if (ReadStatU64(txt, "user_usec", v)) { s.user_usec = v; any = true; }
    if (ReadStatU64(txt, "system_usec", v)) { s.system_usec = v; any = true; }
    if (ReadStatU64(txt, "nr_periods", v)) { s.nr_periods = v; any = true; }
    if (ReadStatU64(txt, "nr_throttled", v)) { s.nr_throttled = v; any = true; }
    if (ReadStatU64(txt, "throttled_usec", v)) { s.throttled_usec = v; any = true; }
    s.cpu_valid = any;
  }

  // memory.current / memory.max / memory.events
  {
    std::string cur = ReadFile(base + "/memory.current");
    uint64_t v = 0;
    bool any = false;
    if (sscanf(cur.c_str(), "%llu", (unsigned long long*)&v) == 1) {
      s.memory_current_bytes = v;
      any = true;
    }
    std::string mx = ReadFile(base + "/memory.max");
    if (mx.find("max") != std::string::npos) {
      s.memory_max_unlimited = true;
      any = true;
    } else if (sscanf(mx.c_str(), "%llu", (unsigned long long*)&v) == 1) {
      s.memory_max_bytes = v;
      any = true;
    }
    std::string ev = ReadFile(base + "/memory.events");
    if (ReadStatU64(ev, "low", v)) { s.memory_events_low = v; any = true; }
    if (ReadStatU64(ev, "high", v)) { s.memory_events_high = v; any = true; }
    if (ReadStatU64(ev, "max", v)) { s.memory_events_max = v; any = true; }
    if (ReadStatU64(ev, "oom", v)) { s.memory_events_oom = v; any = true; }
    if (ReadStatU64(ev, "oom_kill", v)) { s.memory_events_oom_kill = v; any = true; }
    s.memory_valid = any;
  }

  // cpu.pressure / memory.pressure
  s.cpu_psi = ParsePsi(ReadFile(base + "/cpu.pressure"));
  s.memory_psi = ParsePsi(ReadFile(base + "/memory.pressure"));

  // io.stat: "<maj:min> rbytes=.. wbytes=.. rios=.. wios=.. dbytes=.. dios=.."
  {
    std::istringstream is(ReadFile(base + "/io.stat"));
    std::string line;
    while (std::getline(is, line)) {
      std::istringstream ls(line);
      std::string dev;
      if (!(ls >> dev)) continue;
      size_t colon = dev.find(':');
      if (colon == std::string::npos) continue;
      CgroupIOStat io;
      io.major = static_cast<uint32_t>(strtoul(dev.c_str(), nullptr, 10));
      io.minor = static_cast<uint32_t>(strtoul(dev.c_str() + colon + 1, nullptr, 10));
      std::string tok;
      while (ls >> tok) {
        auto num = [&]() -> uint64_t {
          size_t eq = tok.find('=');
          return eq == std::string::npos ? 0 : strtoull(tok.c_str() + eq + 1, nullptr, 10);
        };
        if (tok.rfind("rbytes=", 0) == 0) io.rbytes = num();
        else if (tok.rfind("wbytes=", 0) == 0) io.wbytes = num();
        else if (tok.rfind("rios=", 0) == 0) io.rios = num();
        else if (tok.rfind("wios=", 0) == 0) io.wios = num();
        else if (tok.rfind("dbytes=", 0) == 0) io.dbytes = num();
        else if (tok.rfind("dios=", 0) == 0) io.dios = num();
      }
      s.io.push_back(io);
    }
  }

  return s;
}

bool HostMetrics::ReadVmRss(uint32_t pid, uint64_t& rss_kb) {
  if (pid == 0) return false;
  char path[64];
  snprintf(path, sizeof(path), "/proc/%u/status", pid);
  std::string st = ReadFile(path);
  if (st.empty()) return false;
  size_t pos = st.find("VmRSS:");
  if (pos == std::string::npos) return false;
  unsigned long long v = 0;
  if (sscanf(st.c_str() + pos + 6, "%llu", &v) != 1) return false;
  rss_kb = static_cast<uint64_t>(v);
  return true;
}

std::string HostMetrics::ReadComm(uint32_t pid) {
  if (pid == 0) return {};
  char path[64];
  snprintf(path, sizeof(path), "/proc/%u/comm", pid);
  std::string c = ReadFile(path);
  while (!c.empty() && (c.back() == '\n' || c.back() == '\r')) c.pop_back();
  return c;
}

}  // namespace etrace_diag
