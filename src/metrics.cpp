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

json psi_window(const PsiWindow& w) {
  json j = {{"avg10", w.avg10}, {"avg60", w.avg60}, {"avg300", w.avg300},
            {"some_valid", w.some_valid}, {"full_valid", w.full_valid}};
  return j;
}

}  // namespace

void to_json(json& j, const ProcessRow& r) {
  j = json{{"v", 2},
           {"pid", r.pid},
           {"tgid", r.tgid},
           {"state", r.state},
           {"start_time", r.start_time},
           {"utime", r.utime},
           {"stime", r.stime},
           {"nvcsw", r.nvcsw},
           {"nivcsw", r.nivcsw},
           {"minflt", r.minflt},
           {"majflt", r.majflt},
           {"total_vm", r.total_vm},
           {"rchar", r.rchar},
           {"wchar", r.wchar},
           {"syscr", r.syscr},
           {"syscw", r.syscw},
           {"read_bytes", r.read_bytes},
           {"write_bytes", r.write_bytes},
           {"sum_exec_runtime_ns", r.sum_exec_runtime_ns},
           {"run_delay_ns", r.run_delay_ns},
           {"rss_anon_kb", r.rss_anon_pages * 4},
           {"rss_file_kb", r.rss_file_pages * 4},
           {"rss_shmem_kb", r.rss_shmem_pages * 4},
           {"swap_kb", r.swap_ents * 4},
           {"rss_kb", r.rss_valid ? json(r.rss_kb) : json(nullptr)},
           {"rss_valid", r.rss_valid},
           {"comm", std::string(r.comm)}};
}

void to_json(json& j, const HostSnapshot& s) {
  json cpus = json::array();
  for (const auto& c : s.cpus) {
    cpus.push_back({{"user", c.user}, {"nice", c.nice}, {"system", c.system},
                    {"idle", c.idle}, {"iowait", c.iowait}, {"irq", c.irq},
                    {"softirq", c.softirq}, {"steal", c.steal},
                    {"guest", c.guest}, {"guest_nice", c.guest_nice}});
  }
  json disks = json::array();
  for (const auto& d : s.disks) {
    disks.push_back({{"major", d.major},
                     {"minor", d.minor},
                     {"name", std::string(d.name)},
                     {"reads_completed", d.reads_completed},
                     {"reads_merged", d.reads_merged},
                     {"sectors_read", d.sectors_read},
                     {"read_ticks_ms", d.read_ticks_ms},
                     {"writes_completed", d.writes_completed},
                     {"writes_merged", d.writes_merged},
                     {"sectors_written", d.sectors_written},
                     {"write_ticks_ms", d.write_ticks_ms},
                     {"ios_in_flight", d.ios_in_flight},
                     {"io_ticks_ms", d.io_ticks_ms},
                     {"weighted_ticks_ms", d.weighted_ticks_ms},
                     {"valid_mask", d.valid_mask}});
  }
  json procs = json::array();
  for (const auto& p : s.procs) procs.push_back(p);

  j = json{{"v", 2},
           {"ts_ns", s.ts_ns},
           {"cpus", cpus},
           {"total", {{"user", s.total.user}, {"nice", s.total.nice},
                      {"system", s.total.system}, {"idle", s.total.idle},
                      {"iowait", s.total.iowait}, {"irq", s.total.irq},
                      {"softirq", s.total.softirq}, {"steal", s.total.steal},
                      {"guest", s.total.guest}, {"guest_nice", s.total.guest_nice}}},
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
                    {"anon_pages_kb", s.mem.anon_pages_kb},
                    {"sreclaimable_kb", s.mem.sreclaimable_kb},
                    {"shmem_kb", s.mem.shmem_kb},
                    {"dirty_kb", s.mem.dirty_kb},
                    {"writeback_kb", s.mem.writeback_kb},
                    {"commit_limit_kb", s.mem.commit_limit_kb},
                    {"committed_as_kb", s.mem.committed_as_kb},
                    {"valid_mask", s.mem.valid_mask}}},
           {"vm", {{"pgfault", s.vm.pgfault}, {"pgmajfault", s.vm.pgmajfault},
                   {"pswpin", s.vm.pswpin}, {"pswpout", s.vm.pswpout},
                   {"pgscan_kswapd", s.vm.pgscan_kswapd},
                   {"pgscan_direct", s.vm.pgscan_direct},
                   {"pgsteal_kswapd", s.vm.pgsteal_kswapd},
                   {"pgsteal_direct", s.vm.pgsteal_direct},
                   {"workingset_refault", s.vm.workingset_refault},
                   {"nr_dirty", s.vm.nr_dirty},
                   {"nr_writeback", s.vm.nr_writeback},
                   {"valid_mask", s.vm.valid_mask}}},
           {"psi", {{"cpu", psi_window(s.psi.cpu)},
                    {"io", psi_window(s.psi.io)},
                    {"memory", psi_window(s.psi.memory)}}},
           {"disks", disks},
           {"procs", procs},
           {"ctxt", s.ctxt},
           {"processes", s.processes},
           {"procs_running", s.procs_running},
           {"procs_blocked", s.procs_blocked}};
}

void to_json(json& j, const NetworkSnapshot& s) {
  json ifaces = json::array();
  for (const auto& i : s.ifaces) {
    ifaces.push_back({{"ifindex", i.ifindex},
                      {"name", i.name},
                      {"source", i.source},
                      {"operstate", i.operstate},
                      {"mtu", i.mtu},
                      {"rx_bytes", i.rx_bytes},
                      {"rx_packets", i.rx_packets},
                      {"rx_errors", i.rx_errors},
                      {"rx_dropped", i.rx_dropped},
                      {"tx_bytes", i.tx_bytes},
                      {"tx_packets", i.tx_packets},
                      {"tx_errors", i.tx_errors},
                      {"tx_dropped", i.tx_dropped},
                      {"collisions", i.collisions},
                      {"carrier_changes", i.carrier_changes},
                      {"rx_nohandler", i.rx_nohandler},
                      {"valid", i.valid},
                      {"error", i.error}});
  }
  json softnets = json::array();
  for (const auto& n : s.softnets) {
    softnets.push_back({{"cpu_idx", n.cpu_idx},
                        {"processed", n.processed},
                        {"dropped", n.dropped},
                        {"time_squeeze", n.time_squeeze},
                        {"received_rps", n.received_rps},
                        {"flow_limit_count", n.flow_limit_count},
                        {"backlog_len", n.backlog_len},
                        {"net_rx_softirq", n.net_rx_softirq},
                        {"net_tx_softirq", n.net_tx_softirq},
                        {"valid", n.valid},
                        {"error", n.error}});
  }
  const auto& t = s.stack;
  j = json{{"v", 2},
           {"ts_ns", s.ts_ns},
           {"enabled", s.enabled},
           {"stack", {{"netns_ino", t.netns_ino},
                      {"source", t.source},
                      {"valid", t.valid},
                      {"error", t.error},
                      {"active_opens", t.active_opens},
                      {"passive_opens", t.passive_opens},
                      {"attempt_fails", t.attempt_fails},
                      {"estab_resets", t.estab_resets},
                      {"curr_estab", t.curr_estab},
                      {"in_segs", t.in_segs},
                      {"out_segs", t.out_segs},
                      {"retrans_segs", t.retrans_segs},
                      {"in_errs", t.in_errs},
                      {"out_rsts", t.out_rsts},
                      {"listen_overflows", t.listen_overflows},
                      {"listen_drops", t.listen_drops},
                      {"backlog_drop", t.backlog_drop},
                      {"rcv_q_drop", t.rcv_q_drop},
                      {"syn_retrans", t.syn_retrans},
                      {"timeouts", t.timeouts},
                      {"memory_pressures", t.memory_pressures},
                      {"udp_in_datagrams", t.udp_in_datagrams},
                      {"udp_no_ports", t.udp_no_ports},
                      {"udp_in_errors", t.udp_in_errors},
                      {"udp_out_datagrams", t.udp_out_datagrams},
                      {"udp_rcvbuf_errors", t.udp_rcvbuf_errors},
                      {"udp_sndbuf_errors", t.udp_sndbuf_errors},
                      {"tcp_sock_mem", t.tcp_sock_mem},
                      {"udp_sock_mem", t.udp_sock_mem},
                      {"frag_sock_mem", t.frag_sock_mem},
                      {"tcp_state_established", t.tcp_state_established},
                      {"tcp_state_syn_sent", t.tcp_state_syn_sent},
                      {"tcp_state_syn_recv", t.tcp_state_syn_recv},
                      {"tcp_state_fin_wait1", t.tcp_state_fin_wait1},
                      {"tcp_state_fin_wait2", t.tcp_state_fin_wait2},
                      {"tcp_state_time_wait", t.tcp_state_time_wait},
                      {"tcp_state_close", t.tcp_state_close},
                      {"tcp_state_close_wait", t.tcp_state_close_wait},
                      {"tcp_state_last_ack", t.tcp_state_last_ack},
                      {"tcp_state_listen", t.tcp_state_listen},
                      {"tcp_state_closing", t.tcp_state_closing},
                      {"rqueue_bytes", t.rqueue_bytes},
                      {"wqueue_bytes", t.wqueue_bytes},
                      {"tcp_states_valid", t.tcp_states_valid}}},
           {"ifaces", ifaces},
           {"softnets", softnets}};
}

void to_json(json& j, const CgroupSnapshot& s) {
  json io = json::array();
  for (const auto& d : s.io) {
    io.push_back({{"major", d.major},
                  {"minor", d.minor},
                  {"rbytes", d.rbytes},
                  {"wbytes", d.wbytes},
                  {"rios", d.rios},
                  {"wios", d.wios},
                  {"dbytes", d.dbytes},
                  {"dios", d.dios}});
  }
  j = json{{"v", 2},
           {"ts_ns", s.ts_ns},
           {"available", s.available},
           {"cgroup_path", s.cgroup_path},
           {"error", s.error},
           {"cpu", {{"usage_usec", s.cpu_usage_usec},
                    {"user_usec", s.user_usec},
                    {"system_usec", s.system_usec},
                    {"nr_periods", s.nr_periods},
                    {"nr_throttled", s.nr_throttled},
                    {"throttled_usec", s.throttled_usec},
                    {"valid", s.cpu_valid}}},
           {"memory", {{"current_bytes", s.memory_current_bytes},
                       {"max_bytes", s.memory_max_bytes},
                       {"max_unlimited", s.memory_max_unlimited},
                       {"events_low", s.memory_events_low},
                       {"events_high", s.memory_events_high},
                       {"events_max", s.memory_events_max},
                       {"events_oom", s.memory_events_oom},
                       {"events_oom_kill", s.memory_events_oom_kill},
                       {"valid", s.memory_valid}}},
           {"cpu_psi", psi_window(s.cpu_psi)},
           {"memory_psi", psi_window(s.memory_psi)},
           {"io", io}};
}

void to_json(json& j, const GpuSnapshot& s) {
  json devices = json::array();
  for (const auto& d : s.devices) {
    devices.push_back({{"uuid", d.uuid},
                       {"pci_bdf", d.pci_bdf},
                       {"vendor", d.vendor},
                       {"model", d.model},
                       {"source", d.source},
                       {"available", d.available},
                       {"is_mig", d.is_mig},
                       {"util_pct", d.util_pct},
                       {"mem_util_pct", d.mem_util_pct},
                       {"mem_used_bytes", d.mem_used_bytes},
                       {"mem_total_bytes", d.mem_total_bytes},
                       {"temperature_c", d.temperature_c},
                       {"power_w", d.power_w},
                       {"power_limit_w", d.power_limit_w},
                       {"energy_mj", d.energy_mj},
                       {"sm_clock_mhz", d.sm_clock_mhz},
                       {"mem_clock_mhz", d.mem_clock_mhz},
                       {"pcie_rx_kbps", d.pcie_rx_kbps},
                       {"pcie_tx_kbps", d.pcie_tx_kbps},
                       {"encoder_util_pct", d.encoder_util_pct},
                       {"decoder_util_pct", d.decoder_util_pct},
                       {"throttle_reasons", d.throttle_reasons},
                       {"ecc_sbe_total", d.ecc_sbe_total},
                       {"ecc_dbe_total", d.ecc_dbe_total},
                       {"retired_pages", d.retired_pages},
                       {"error_code", d.error_code},
                       {"error_text", d.error_text},
                       {"valid_mask", d.valid_mask}});
  }
  j = json{{"v", 2}, {"ts_ns", s.ts_ns}, {"devices", devices}};
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
  j = json{{"v", 2},
           {"ts_ns", c.ts_ns},
           {"on_cpu_ns_total", c.on_cpu_ns_total},
           {"switch_total", c.switch_total},
           {"io_ops_total", c.io_ops_total},
           {"io_bytes_total", c.io_bytes_total},
           {"minor_faults_total", c.minor_faults_total},
           {"major_faults_total", c.major_faults_total},
           {"lock_waits_total", c.lock_waits_total},
           {"per_tid", per_tid}};
}

void to_json(json& j, const DeepProcessRow& r) {
  j = json{{"v", 2},
           {"ordinal", r.ordinal},
           {"ts_ns", r.ts_ns},
           {"tid", r.tid},
           {"tgid", r.tgid},
           {"comm", r.comm},
           {"vm_rss_kb", r.status_valid ? json(r.vm_rss_kb) : json(nullptr)},
           {"rss_anon_kb", r.status_valid ? json(r.rss_anon_kb) : json(nullptr)},
           {"rss_file_kb", r.status_valid ? json(r.rss_file_kb) : json(nullptr)},
           {"rss_shmem_kb", r.status_valid ? json(r.rss_shmem_kb) : json(nullptr)},
           {"vm_swap_kb", r.status_valid ? json(r.vm_swap_kb) : json(nullptr)},
           {"status_valid", r.status_valid},
           {"rchar", r.io_valid ? json(r.rchar) : json(nullptr)},
           {"wchar", r.io_valid ? json(r.wchar) : json(nullptr)},
           {"read_bytes", r.io_valid ? json(r.read_bytes) : json(nullptr)},
           {"write_bytes", r.io_valid ? json(r.write_bytes) : json(nullptr)},
           {"syscr", r.io_valid ? json(r.syscr) : json(nullptr)},
           {"syscw", r.io_valid ? json(r.syscw) : json(nullptr)},
           {"io_valid", r.io_valid},
           {"sched_exec_runtime_ns", r.sched_valid ? json(r.sched_exec_runtime_ns) : json(nullptr)},
           {"sched_run_delay_ns", r.sched_valid ? json(r.sched_run_delay_ns) : json(nullptr)},
           {"sched_switch_count", r.sched_valid ? json(r.sched_switch_count) : json(nullptr)},
           {"sched_valid", r.sched_valid},
           {"available", r.available},
           {"error", r.error}};
}

void to_json(json& j, const DeepIoDeviceRow& r) {
  j = json{{"v", 2},
           {"ordinal", r.ordinal},
           {"dev", r.dev},
           {"ops", r.ops},
           {"bytes", r.bytes},
           {"lat_sum", r.lat_sum},
           {"hist", hist13(r.hist)},
           {"p50_us", r.p50_us},
           {"p99_us", r.p99_us}};
}

void to_json(json& j, const DeepOffcpuRow& r) {
  j = json{{"v", 2},
           {"ordinal", r.ordinal},
           {"tid", r.tid},
           {"tgid", r.tgid},
           {"comm", r.comm},
           {"dwell_ns", r.dwell_ns},
           {"count", r.count},
           {"stack_available", r.stack_available}};
}

void to_json(json& j, const DeepNetFlowRow& r) {
  j = json{{"v", 2},
           {"ordinal", r.ordinal},
           {"cookie", r.cookie},
           {"tgid", r.tgid},
           {"tid", r.tid},
           {"netns_ino", r.netns_ino},
           {"family", r.family},
           {"local_addr", r.local_addr},
           {"local_port", r.local_port},
           {"remote_addr", r.remote_addr},
           {"remote_port", r.remote_port},
           {"final_state", r.final_state},
           {"start_ts_ns", r.start_ts_ns},
           {"established_ts_ns", r.established_ts_ns},
           {"end_ts_ns", r.end_ts_ns},
           {"duration_us", r.duration_us},
           {"connect_latency_us", r.connect_latency_us},
           {"tx_bytes", r.tx_bytes},
           {"rx_bytes", r.rx_bytes},
           {"retransmits", r.retransmits},
           {"rst_reason", r.rst_reason},
           {"rtt_count", r.rtt_count},
           {"rtt_avg_us", r.rtt_avg_us},
           {"rtt_p50_us", r.rtt_p50_us},
           {"rtt_p99_us", r.rtt_p99_us},
           {"closed", r.closed},
           {"owner_available", r.owner_available},
           {"error", r.error}};
}

void to_json(json& j, const DeepNetDropRow& r) {
  j = json{{"v", 2},
           {"ordinal", r.ordinal},
           {"netns_ino", r.netns_ino},
           {"ifindex", r.ifindex},
           {"reason_id", r.reason_id},
           {"reason", r.reason},
           {"count", r.count}};
}

void to_json(json& j, const DeepNetSoftirqRow& r) {
  j = json{{"v", 2},
           {"ordinal", r.ordinal},
           {"cpu_idx", r.cpu_idx},
           {"vector", r.vector},
           {"vector_name", r.vector_name},
           {"count", r.count},
           {"time_ns", r.time_ns},
           {"hist", r.hist}};
}

void to_json(json& j, const DeepGpuProcessRow& r) {
  j = json{{"v", 2},
           {"ordinal", r.ordinal},
           {"ts_ns", r.ts_ns},
           {"gpu_uuid", r.gpu_uuid},
           {"pid", r.pid},
           {"tgid", r.tgid},
           {"comm", r.comm},
           {"source", r.source},
           {"sm_util_pct", r.sm_util_pct},
           {"mem_util_pct", r.mem_util_pct},
           {"enc_util_pct", r.enc_util_pct},
           {"dec_util_pct", r.dec_util_pct},
           {"fb_used_bytes", r.fb_used_bytes},
           {"source_ts_us", r.source_ts_us},
           {"valid_mask", r.valid_mask},
           {"error", r.error}};
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
  j = json{{"v", 2},
           {"ts_ns", s.ts_ns},
           {"interval_ns", s.interval_ns},
           {"stats_enabled", s.stats_enabled},
           {"total_run_time_ns", total_ns},
           {"total_run_cnt", total_cnt},
           {"progs", progs}};
}

void to_json(json& j, const ProcOverhead& s) {
  j = json{{"v", 2},
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
  j = json{{"v", 2},
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
