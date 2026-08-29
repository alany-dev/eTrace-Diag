#include "etrace_diag/metrics.h"

#include <nlohmann/json.hpp>

namespace etrace_diag {

using nlohmann::json;

namespace {
json hist13(const uint32_t h[kBase4HistBins]) {
  json a = json::array();
  for (int i = 0; i < kBase4HistBins; ++i) a.push_back(h[i]);
  return a;
}
}  // namespace

void to_json(json& j, const ProcessRow& r) {
  j = json{{"v", 1},
           {"pid", r.pid},
           {"tgid", r.tgid},
           {"state", r.state},
           {"start_time", r.start_time},
           {"utime", r.utime},
           {"stime", r.stime},
           {"nvcsw", r.nvcsw},
           {"nivcsw", r.nivcsw},
           {"total_vm", r.total_vm},
           {"rss_kb", r.rss_kb},
           {"comm", std::string(r.comm)}};
}

void to_json(json& j, const HostSnapshot& s) {
  json cpus = json::array();
  for (const auto& c : s.cpus) {
    cpus.push_back({{"user", c.user},    {"nice", c.nice},       {"system", c.system},
                    {"idle", c.idle},    {"iowait", c.iowait},   {"irq", c.irq},
                    {"softirq", c.softirq}, {"steal", c.steal}});
  }
  json disks = json::array();
  for (const auto& d : s.disks) {
    disks.push_back({{"major", d.major},
                     {"minor", d.minor},
                     {"name", std::string(d.name)},
                     {"reads_completed", d.reads_completed},
                     {"writes_completed", d.writes_completed},
                     {"sectors_read", d.sectors_read},
                     {"sectors_written", d.sectors_written},
                     {"io_ticks_ms", d.io_ticks_ms},
                     {"read_ticks_ms", d.read_ticks_ms},
                     {"write_ticks_ms", d.write_ticks_ms}});
  }
  json procs = json::array();
  for (const auto& p : s.procs) procs.push_back(p);

  j = json{{"v", 1},
           {"ts_ns", s.ts_ns},
           {"cpus", cpus},
           {"total", {{"user", s.total.user}, {"nice", s.total.nice},
                      {"system", s.total.system}, {"idle", s.total.idle},
                      {"iowait", s.total.iowait}, {"irq", s.total.irq},
                      {"softirq", s.total.softirq}, {"steal", s.total.steal}}},
           {"load", {{"load1", s.load.load1}, {"load5", s.load.load5},
                     {"load15", s.load.load15}, {"nr_running", s.load.nr_running},
                     {"nr_threads", s.load.nr_threads}}},
           {"mem", {{"mem_total_kb", s.mem.mem_total_kb},
                    {"mem_available_kb", s.mem.mem_available_kb},
                    {"mem_free_kb", s.mem.mem_free_kb},
                    {"buffers_kb", s.mem.buffers_kb},
                    {"cached_kb", s.mem.cached_kb},
                    {"swap_total_kb", s.mem.swap_total_kb},
                    {"swap_free_kb", s.mem.swap_free_kb},
                    {"anon_pages_kb", s.mem.anon_pages_kb}}},
           {"vm", {{"pgfault", s.vm.pgfault}, {"pgmajfault", s.vm.pgmajfault},
                   {"pswpin", s.vm.pswpin}, {"pswpout", s.vm.pswpout},
                   {"nr_free_pages", s.vm.nr_free_pages},
                   {"nr_anon_pages", s.vm.nr_anon_pages}}},
           {"psi", {{"cpu", {{"avg10", s.psi.cpu10}, {"avg60", s.psi.cpu60},
                             {"avg300", s.psi.cpu300}}},
                    {"io", {{"avg10", s.psi.io10}, {"avg60", s.psi.io60},
                            {"avg300", s.psi.io300}}},
                    {"mem", {{"avg10", s.psi.mem10}, {"avg60", s.psi.mem60},
                             {"avg300", s.psi.mem300}}}}},
           {"disks", disks},
           {"procs", procs}};
}

void to_json(json& j, const EbpfCounters& c) {
  json per_tid = json::array();
  for (const auto& t : c.per_tid) {
    per_tid.push_back({{"tid", t.tid}, {"on_cpu_ns", t.on_cpu_ns},
                       {"nr_sw_vol", t.nr_sw_vol}, {"nr_sw_invol", t.nr_sw_invol},
                       {"io_ops", t.io_ops}, {"io_bytes", t.io_bytes},
                       {"pf_minor", t.pf_minor}, {"pf_major", t.pf_major},
                       {"lock_waits", t.lock_waits}, {"lock_lat_ns", t.lock_lat_ns}});
  }
  j = json{{"v", 1},
           {"ts_ns", c.ts_ns},
           {"on_cpu_ns_total", c.on_cpu_ns_total},
           {"switch_total", c.switch_total},
           {"io_ops_total", c.io_ops_total},
           {"io_bytes_total", c.io_bytes_total},
           {"faults_total", c.faults_total},
           {"lock_waits_total", c.lock_waits_total},
           {"per_tid", per_tid}};
}

void to_json(json& j, const BpfProgStats& s) {
  j = json{{"name", s.name},
           {"id", s.id},
           {"run_cnt", s.run_cnt},
           {"run_time_ns", s.run_time_ns},
           {"avg_ns", s.run_cnt ? (double)s.run_time_ns / (double)s.run_cnt : 0.0}};
}

void to_json(json& j, const BpfStatsSnapshot& s) {
  json progs = json::array();
  uint64_t total_ns = 0, total_cnt = 0;
  for (const auto& p : s.progs) {
    progs.push_back(p);
    total_ns += p.run_time_ns;
    total_cnt += p.run_cnt;
  }
  j = json{{"v", 1},
           {"ts_ns", s.ts_ns},
           {"interval_ns", s.interval_ns},
           {"stats_enabled", s.stats_enabled},
           {"total_run_time_ns", total_ns},
           {"total_run_cnt", total_cnt},
           {"progs", progs}};
}

void to_json(json& j, const ProcOverhead& s) {
  j = json{{"v", 1},
           {"ts_ns", s.ts_ns},
           {"utime_ns", s.utime_ns},
           {"stime_ns", s.stime_ns},
           {"cpu_ns", s.utime_ns + s.stime_ns},
           {"nvcsw", s.nvcsw},
           {"nivcsw", s.nivcsw},
           {"minflt", s.minflt},
           {"majflt", s.majflt},
           {"rss_kb", s.rss_kb},
           {"vmhwm_kb", s.vmhwm_kb}};
}

void to_json(json& j, const CanonicalSnapshot& s) {
  j = json{{"v", 1},
           {"ts_ns", s.ts_ns},
           {"tgid", s.tgid},
           {"tid", s.tid},
           {"comm", std::string(s.comm)},
           {"on_cpu_ns", s.on_cpu_ns},
           {"nr_sw_vol", s.nr_sw_vol},
           {"nr_sw_invol", s.nr_sw_invol},
           {"io_ops", s.io_ops},
           {"io_bytes", s.io_bytes},
           {"io_hist", hist13(s.io_hist)},
           {"pf_minor", s.pf_minor},
           {"pf_major", s.pf_major},
           {"lock_waits", s.lock_waits},
           {"lock_lat_ns", s.lock_lat_ns},
           {"lock_hist", hist13(s.lock_hist)},
           {"syscall_count", s.syscall_count},
           {"syscall_lat_ns", s.syscall_lat_ns},
           {"syscall_hist", hist13(s.syscall_hist)},
           {"futex_waits", s.futex_waits},
           {"futex_lat_ns", s.futex_lat_ns},
           {"futex_hist", hist13(s.futex_hist)},
           {"runq_wait_ns", s.runq_wait_ns},
           {"runq_wait_count", s.runq_wait_count},
           {"runq_hist", hist13(s.runq_hist)},
           {"flags", s.flags}};
}

}  // namespace etrace_diag