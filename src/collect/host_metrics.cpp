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

// Parses a /proc/stat cpu line: "cpuN  user nice system idle iowait irq softirq steal ..."
bool ParseCpuLine(const std::string& line, CpuStat& out) {
  std::istringstream is(line);
  std::string label;
  is >> label;
  if (label.rfind("cpu", 0) != 0) return false;
  return static_cast<bool>(is >> out.user >> out.nice >> out.system >> out.idle >> out.iowait >>
                           out.irq >> out.softirq >> out.steal);
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

long long VmstatValue(const std::string& text, const char* key) {
  size_t pos = 0;
  size_t klen = strlen(key);
  while ((pos = text.find(key, pos)) != std::string::npos) {
    size_t ws = pos + klen;
    // ensure token boundary
    if (pos == 0 || text[pos - 1] == '\n') {
      long long v = 0;
      if (sscanf(text.c_str() + ws, "%lld", &v) == 1) return v;
    }
    pos += klen;
  }
  return 0;
}

bool ParsePsi(const std::string& text, const char* kind, PsiSnapshot& psi) {
  size_t pos = text.find(kind);
  if (pos == std::string::npos) return false;
  // find the "full" line following the "some" line
  size_t full = text.find("full", pos);
  if (full == std::string::npos) return false;
  size_t eol = text.find('\n', full);
  if (eol == std::string::npos) eol = text.size();
  std::string line = text.substr(full, eol - full);
  auto readv = [&](const char* k) -> double {
    size_t p = line.find(k);
    if (p == std::string::npos) return 0.0;
    double v = 0;
    if (sscanf(line.c_str() + p + strlen(k), "%lf", &v) == 1) return v;
    return 0.0;
  };
  double a10 = readv("avg10="), a60 = readv("avg60="), a300 = readv("avg300=");
  if (strcmp(kind, "cpu") == 0) { psi.cpu10 = a10; psi.cpu60 = a60; psi.cpu300 = a300; }
  else if (strcmp(kind, "io") == 0) { psi.io10 = a10; psi.io60 = a60; psi.io300 = a300; }
  else if (strcmp(kind, "memory") == 0) { psi.mem10 = a10; psi.mem60 = a60; psi.mem300 = a300; }
  return true;
}

}  // namespace

HostSnapshot HostMetrics::Snapshot() {
  HostSnapshot s;
  s.ts_ns = NowNs();

  // /proc/stat — per-cpu + aggregate
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
        if (ls >> t.user >> t.nice >> t.system >> t.idle >> t.iowait >> t.irq >> t.softirq >> t.steal)
          s.total = t;
      } else if (line.rfind("cpu", 0) == 0) {
        CpuStat c;
        if (ParseCpuLine(line, c)) s.cpus.push_back(c);
      } else if (line.rfind("intr", 0) == 0 || line.rfind("ctxt", 0) == 0 ||
                 line.rfind("btime", 0) == 0 || line.rfind("processes", 0) == 0) {
        continue;
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

  // /proc/meminfo
  {
    std::string mi = ReadFile("/proc/meminfo");
    MeminfoValue(mi, "MemTotal", s.mem.mem_total_kb);
    MeminfoValue(mi, "MemAvailable", s.mem.mem_available_kb);
    MeminfoValue(mi, "MemFree", s.mem.mem_free_kb);
    MeminfoValue(mi, "Buffers", s.mem.buffers_kb);
    MeminfoValue(mi, "Cached", s.mem.cached_kb);
    MeminfoValue(mi, "SwapTotal", s.mem.swap_total_kb);
    MeminfoValue(mi, "SwapFree", s.mem.swap_free_kb);
    MeminfoValue(mi, "AnonPages", s.mem.anon_pages_kb);
  }

  // /proc/vmstat
  {
    std::string vs = ReadFile("/proc/vmstat");
    s.vm.pgfault = static_cast<uint64_t>(VmstatValue(vs, "pgfault"));
    s.vm.pgmajfault = static_cast<uint64_t>(VmstatValue(vs, "pgmajfault"));
    s.vm.pswpin = static_cast<uint64_t>(VmstatValue(vs, "pswpin"));
    s.vm.pswpout = static_cast<uint64_t>(VmstatValue(vs, "pswpout"));
    s.vm.nr_free_pages = static_cast<uint64_t>(VmstatValue(vs, "nr_free_pages"));
    s.vm.nr_anon_pages = static_cast<uint64_t>(VmstatValue(vs, "nr_anon_pages"));
  }

  // /proc/pressure/{cpu,io,memory} — "full" PSI
  {
    ParsePsi(ReadFile("/proc/pressure/cpu"), "cpu", s.psi);
    ParsePsi(ReadFile("/proc/pressure/io"), "io", s.psi);
    ParsePsi(ReadFile("/proc/pressure/memory"), "memory", s.psi);
  }

  // /proc/diskstats — per-device cumulative counters. Kernel 4.18+ layout
  // (after major/minor/name): reads_completed reads_merged sectors_read
  // read_ticks_ms writes_completed writes_merged sectors_written write_ticks_ms
  // ios_in_flight io_ticks_ms weighted_ticks_ms.
  {
    std::istringstream is(ReadFile("/proc/diskstats"));
    std::string line;
    while (std::getline(is, line)) {
      if (line.empty()) continue;
      std::istringstream ls(line);
      DiskStatRow d;
      std::string name;
      unsigned long long reads_merged = 0, writes_merged = 0, inflight = 0, weighted = 0;
      if (!(ls >> d.major >> d.minor >> name)) continue;
      bool ok = static_cast<bool>(ls >> d.reads_completed >> reads_merged >> d.sectors_read >>
                                  d.read_ticks_ms >> d.writes_completed >> writes_merged >>
                                  d.sectors_written >> d.write_ticks_ms >> inflight >>
                                  d.io_ticks_ms >> weighted);
      (void)reads_merged; (void)writes_merged; (void)inflight; (void)weighted;
      if (!ok) continue;
      snprintf(d.name, sizeof(d.name), "%s", name.c_str());
      s.disks.push_back(d);
    }
  }

  return s;
}

uint64_t HostMetrics::ReadVmRss(uint32_t pid) {
  if (pid == 0) return 0;
  char path[64];
  snprintf(path, sizeof(path), "/proc/%u/status", pid);
  std::string st = ReadFile(path);
  if (st.empty()) return 0;
  size_t pos = st.find("VmRSS:");
  if (pos == std::string::npos) return 0;
  unsigned long long v = 0;
  if (sscanf(st.c_str() + pos + 6, "%llu", &v) != 1) return 0;
  return static_cast<uint64_t>(v);
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