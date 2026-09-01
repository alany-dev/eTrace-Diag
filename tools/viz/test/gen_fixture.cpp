// Root-free end-to-end exercise of OutputWriter: creates a v2 session DB and
// writes realistic rows through every public API, so the SQLite layer is
// verified without BPF/root. Built with writer.cpp + logging.cpp.
#include "etrace_diag/config.h"
#include "etrace_diag/metrics.h"
#include "etrace_diag/output_writer.h"

#include <cstdio>
#include <cstring>

using namespace etrace_diag;

int main(int argc, char** argv) {
  Config cfg = DefaultConfig();
  cfg.output.dir = argc > 1 ? argv[1] : "out_fixture";

  OutputWriter writer;
  if (!writer.Init(cfg)) {
    fprintf(stderr, "fixture: writer.Init failed\n");
    return 1;
  }

  // ---- two base ticks: host + network + gpu + cgroup ----
  for (int tick = 0; tick < 2; ++tick) {
    HostSnapshot h;
    h.ts_ns = 1000000000ULL * (tick + 1);
    h.total = {100ULL + tick * 20ULL, 5ULL, 30ULL + tick * 10ULL, 400ULL, 2ULL, 3ULL, 4ULL, 1ULL, 0ULL, 0ULL};
    h.ctxt = 1000 + tick * 10;
    h.processes = 50 + tick;
    h.procs_running = 2;
    h.procs_blocked = 0;
    h.load = {0.5, 0.4, 0.3, 2, 200};
    h.mem = {};
    h.mem.mem_total_kb = 16000000;
    h.mem.mem_available_kb = 8000000;
    h.mem.mem_free_kb = 4000000;
    h.mem.buffers_kb = 100;
    h.mem.cached_kb = 2000;
    h.mem.swap_total_kb = 1000;
    h.mem.swap_free_kb = 900;
    h.mem.anon_pages_kb = 3000;
    h.mem.sreclaimable_kb = 50;
    h.mem.shmem_kb = 60;
    h.mem.dirty_kb = 10;
    h.mem.writeback_kb = 0;
    h.mem.commit_limit_kb = 20000000;
    h.mem.committed_as_kb = 5000000;
    h.mem.valid_mask = 0x3FFF;
    h.vm = {};
    h.vm.pgfault = 1000 + tick * 100;
    h.vm.pgmajfault = 2;
    h.vm.pswpin = 0;
    h.vm.pswpout = 0;
    h.vm.pgscan_kswapd = 5;
    h.vm.pgscan_direct = 1;
    h.vm.pgsteal_kswapd = 4;
    h.vm.pgsteal_direct = 1;
    h.vm.workingset_refault = 7;
    h.vm.nr_dirty = 10;
    h.vm.nr_writeback = 0;
    h.vm.valid_mask = 0x7FF;
    h.psi.cpu = {1.0, 0.8, 0.6, true, false};
    h.psi.io = {2.0, 1.5, 1.0, true, true};
    h.psi.memory = {0.0, 0.0, 0.0, true, true};
    DiskStatRow d = {};
    d.major = 8; d.minor = 0;
    snprintf(d.name, sizeof(d.name), "sda");
    d.reads_completed = 100;
    d.writes_completed = 50;
    d.sectors_read = 4000;
    d.sectors_written = 2000;
    d.io_ticks_ms = 500;
    d.read_ticks_ms = 300;
    d.write_ticks_ms = 200;
    d.reads_merged = 10;
    d.writes_merged = 5;
    d.ios_in_flight = 1;
    d.weighted_ticks_ms = 600;
    d.valid_mask = 0x7FF;
    h.disks.push_back(d);
    ProcessRow p = {};
    p.pid = 4242; p.tgid = 4242;
    p.state = 0;
    p.start_time = 100;
    p.utime = 50 + tick * 5;
    p.stime = 10;
    p.nvcsw = 3;
    p.nivcsw = 4;
    p.minflt = 20;
    p.majflt = 1;
    p.total_vm = 1000;
    p.rss_kb = 4096;
    p.rss_valid = true;
    snprintf(p.comm, sizeof(p.comm), "fixture");
    h.procs.push_back(p);

    NetworkSnapshot n;
    n.ts_ns = h.ts_ns;
    n.enabled = true;
    n.stack.valid = true;
    n.stack.source = "procfs";
    n.stack.netns_ino = 4026531840ULL;
    n.stack.active_opens = 100 + tick * 5;
    n.stack.passive_opens = 50;
    n.stack.attempt_fails = 1;
    n.stack.estab_resets = 2;
    n.stack.curr_estab = 10 + tick;
    n.stack.in_segs = 1000 + tick * 100;
    n.stack.out_segs = 800;
    n.stack.retrans_segs = 3;
    n.stack.in_errs = 0;
    n.stack.out_rsts = 1;
    n.stack.listen_overflows = 0;
    n.stack.listen_drops = 0;
    n.stack.backlog_drop = 0;
    n.stack.rcv_q_drop = 0;
    n.stack.syn_retrans = 1;
    n.stack.timeouts = 2;
    n.stack.memory_pressures = 0;
    n.stack.udp_in_datagrams = 50;
    n.stack.udp_no_ports = 0;
    n.stack.udp_in_errors = 0;
    n.stack.udp_out_datagrams = 40;
    n.stack.udp_rcvbuf_errors = 0;
    n.stack.udp_sndbuf_errors = 0;
    n.stack.tcp_sock_mem = 128;
    n.stack.udp_sock_mem = 8;
    n.stack.frag_sock_mem = 0;
    n.stack.tcp_states_valid = true;
    n.stack.tcp_state_established = 10 + tick;
    n.stack.tcp_state_listen = 2;
    n.stack.rqueue_bytes = 100;
    n.stack.wqueue_bytes = 0;
    NetInterfaceRow lo = {};
    lo.ifindex = 1;
    lo.name = "lo";
    lo.source = "netlink";
    lo.operstate = 6;
    lo.mtu = 65536;
    lo.rx_bytes = 1000 + tick * 1000;
    lo.rx_packets = 10 + tick * 10;
    lo.tx_bytes = 500 + tick * 500;
    lo.tx_packets = 5 + tick * 5;
    lo.valid = true;
    n.ifaces.push_back(lo);
    NetSoftnetRow sn = {};
    sn.cpu_idx = 0;
    sn.processed = 100 + tick * 10;
    sn.dropped = 0;
    sn.time_squeeze = 1;
    sn.backlog_len = 0;
    sn.net_rx_softirq = 200;
    sn.net_tx_softirq = 100;
    sn.valid = true;
    n.softnets.push_back(sn);

    GpuSnapshot g;
    g.ts_ns = h.ts_ns;
    GpuDeviceRow gd = {};
    gd.uuid = "GPU-deadbeef";
    gd.source = "off";
    gd.available = false;
    gd.error_text = "disabled";
    g.devices.push_back(gd);
    GpuDeviceRow un = {};
    un.uuid = "unavailable";
    un.source = "nvml";
    un.available = false;
    un.error_text = "libnvidia-ml.so.1 missing";
    g.devices.push_back(un);

    CgroupSnapshot cg;
    cg.ts_ns = h.ts_ns;
    cg.available = true;
    cg.cgroup_path = "/";
    cg.cpu_valid = true;
    cg.cpu_usage_usec = 1000 + tick * 100;
    cg.user_usec = 600;
    cg.system_usec = 400;
    cg.nr_periods = 10;
    cg.nr_throttled = 1;
    cg.throttled_usec = 500;
    cg.memory_valid = true;
    cg.memory_current_bytes = 300000000ULL;
    cg.memory_max_unlimited = true;
    cg.memory_events_oom = tick;
    CgroupIOStat cio = {};
    cio.major = 8; cio.minor = 0;
    cio.rbytes = 1000; cio.wbytes = 500;
    cio.rios = 10; cio.wios = 5;
    cg.io.push_back(cio);

    writer.BeginBatch();
    writer.WriteHostRow(h, n, g, cg);
    writer.CommitBatch();
  }

  // ---- anomaly features (v2 keys; lock_lat_ns > 0) ----
  {
    nlohmann::json per_tid = nlohmann::json::array();
    per_tid.push_back({{"tid", 4242}, {"on_cpu_ns", 50000000ULL}, {"nr_sw_vol", 3},
                       {"nr_sw_invol", 4}, {"io_ops", 10}, {"io_bytes", 4096},
                       {"pf_minor", 20}, {"pf_major", 1}, {"lock_waits", 2},
                       {"lock_lat_ns", 1234567ULL}});
    nlohmann::json f = {{"v", 2},
                        {"ts_ns", 2000000000ULL},
                        {"seq", 0},
                        {"ebpf", {{"on_cpu_ns_total", 50000000ULL},
                                  {"switch_total", 7},
                                  {"io_ops_total", 10},
                                  {"io_bytes_total", 4096},
                                  {"minor_faults_total", 20},
                                  {"major_faults_total", 1},
                                  {"lock_waits_total", 2},
                                  {"per_tid", per_tid}}}};
    writer.BeginBatch();
    writer.WriteAnomalyFeatures(f);
    writer.CommitBatch();
  }

  // ---- DEEP episode with every v2 evidence row kind ----
  if (!writer.OpenDeep(1)) {
    fprintf(stderr, "fixture: OpenDeep failed\n");
    return 1;
  }
  {
    CanonicalSnapshot s;
    s.ts_ns = 3000000000ULL;
    s.tgid = 4242;
    s.tid = 4242;
    snprintf(s.comm, sizeof(s.comm), "fixture");
    s.on_cpu_ns = 10000000ULL;
    s.pf_minor = 5;
    writer.BeginBatch();
    writer.WritePreSeries(s);
    writer.CommitBatch();
  }
  {
    writer.BeginBatch();
    writer.WriteDeepSyscall(4242, 0 /*read*/, 100, 1.5f, 1.0f, 3.0f, 2);
    writer.WriteDeepLock(0xffff888000000000ULL, 10, 5000000ULL, "mutex_lock");
    writer.WriteDeepRunq(4242, 20, 2.0f, 1.5f, 4.0f);
    uint32_t hist[kBase4HistBins] = {1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    writer.WriteDeepIoFile(8, 12345, "/tmp/fixture.dat", 4096, 10, 1, 50000, hist, 2.0f, 8.0f);
    writer.CommitBatch();
  }
  {
    writer.BeginBatch();
    DeepProcessRow pr;
    pr.ordinal = 1;
    pr.ts_ns = 3000000000ULL;
    pr.tid = 4242;
    pr.tgid = 4242;
    pr.comm = "fixture";
    pr.vm_rss_kb = 4096;
    pr.rss_anon_kb = 3000;
    pr.rss_file_kb = 1000;
    pr.rss_shmem_kb = 96;
    pr.vm_swap_kb = 0;
    pr.status_valid = true;
    pr.rchar = 10000;
    pr.wchar = 5000;
    pr.read_bytes = 4096;
    pr.write_bytes = 0;
    pr.syscr = 100;
    pr.syscw = 1;
    pr.io_valid = true;
    pr.sched_exec_runtime_ns = 40000000ULL;
    pr.sched_run_delay_ns = 100000ULL;
    pr.sched_switch_count = 20;
    pr.sched_valid = true;
    pr.available = true;
    writer.WriteDeepProcess(pr);
    DeepProcessRow dead;
    dead.ordinal = 1;
    dead.ts_ns = 3000000000ULL;
    dead.tid = 9999;
    dead.tgid = 9999;
    dead.available = false;
    dead.error = "no /proc";
    writer.WriteDeepProcess(dead);

    DeepIoDeviceRow dio;
    dio.ordinal = 1;
    dio.dev = (8u << 8);
    dio.ops = 100;
    dio.bytes = 4096;
    dio.lat_sum = 5000000ULL;
    for (int i = 0; i < kBase4HistBins; ++i) dio.hist[i] = i + 1;
    dio.p50_us = 50.0f;
    dio.p99_us = 200.0f;
    writer.WriteDeepIoDevice(dio);

    DeepNetFlowRow flow;
    flow.ordinal = 1;
    flow.cookie = 0xdeadULL;
    flow.tgid = 4242;
    flow.tid = 4242;
    flow.netns_ino = 4026531840ULL;
    flow.family = 2;   // AF_INET
    flow.local_addr = 0x0100007f;
    flow.local_port = 8080;
    flow.remote_addr = 0x0100007f;
    flow.remote_port = 50000;
    flow.final_state = 7;  // TCP_CLOSE
    flow.start_ts_ns = 3000000000ULL;
    flow.established_ts_ns = 3005000000ULL;
    flow.end_ts_ns = 3100000000ULL;
    flow.connect_latency_us = 5000;
    flow.tx_bytes = 4096;
    flow.rx_bytes = 8192;
    flow.retransmits = 1;
    flow.rst_reason = 0;
    flow.rtt_count = 4;
    flow.rtt_avg_us = 200;
    flow.closed = true;
    flow.owner_available = true;
    writer.WriteDeepNetFlow(flow);
    DeepNetFlowRow open_flow = flow;
    open_flow.cookie = 0xbeefULL;
    open_flow.closed = false;
    open_flow.owner_available = false;
    writer.WriteDeepNetFlow(open_flow);

    DeepNetDropRow drop;
    drop.ordinal = 1;
    drop.netns_ino = 4026531840ULL;
    drop.ifindex = 2;
    drop.reason_id = 1;
    drop.reason = "protocol";
    drop.count = 3;
    writer.WriteDeepNetDrop(drop);

    DeepNetSoftirqRow soft;
    soft.ordinal = 1;
    soft.cpu_idx = 0;
    soft.vector = 3;
    soft.vector_name = "NET_RX";
    soft.count = 100;
    soft.time_ns = 200000ULL;
    soft.hist = "[1,2,3]";
    writer.WriteDeepNetSoftirq(soft);

    DeepGpuProcessRow gp;
    gp.ordinal = 1;
    gp.ts_ns = 3000000000ULL;
    gp.gpu_uuid = "GPU-deadbeef";
    gp.pid = 4242;
    gp.tgid = 4242;
    gp.comm = "fixture";
    gp.source = "nvml";
    gp.mem_util_pct = 10.0;
    gp.fb_used_bytes = 1073741824ULL;
    gp.valid_mask = (1u << 1) | (1u << 4);
    writer.WriteDeepGpuProcess(gp);

    DeepOffcpuRow off;
    off.ordinal = 1;
    off.tid = 4242;
    off.tgid = 4242;
    off.comm = "fixture";
    off.dwell_ns = 100000000ULL;
    off.count = 5;
    off.stack_available = 0;
    writer.WriteDeepOffcpu(off);
    writer.CommitBatch();
  }
  {
    writer.BeginBatch();
    writer.WriteFoldedLine("on_cpu", "p:4242/fixture;t:4242/fixture;start_kernel;schedule", 10);
    writer.CommitBatch();
  }
  {
    nlohmann::json meta = {{"v", 2},
                           {"anomaly_start_ts", 3000000000ULL},
                           {"anomaly_end_ts", 3200000000ULL},
                           {"deep_ordinal", 1},
                           {"capabilities", nlohmann::json::array()}};
    writer.WriteMeta(meta);
    writer.WriteSummary("fixture summary\n");
  }
  writer.CloseDeep();

  writer.Close();
  printf("%s\n", writer.session_dir().c_str());
  return 0;
}
