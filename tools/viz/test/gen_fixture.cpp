// Root-free end-to-end exercise of OutputWriter: creates a session DB and
// writes realistic rows through every public API, so the SQLite layer is
// verified without BPF/root. Built with writer.cpp + logging.cpp.
#include "etrace_diag/output_writer.h"
#include "etrace_diag/metrics.h"
#include "etrace_diag/config.h"

#include <cstdio>

using namespace etrace_diag;

int main() {
  Config cfg;
  cfg.output.dir = "out_writer_test";
  OutputWriter w;
  if (!w.Init(cfg)) { fprintf(stderr, "Init failed\n"); return 1; }

  w.WriteLogLine("[2026-08-29T14:00:01.123Z] [INFO] harness line 1");
  w.WriteLogLine("[2026-08-29T14:00:02.456Z] [WARN] target join tid=100 score=0.90");
  w.WriteLogLine("[2026-08-29T14:00:03.789Z] [ERROR] oom killer invoked");

  // host row (host + host_cpu + host_disk + host_proc)
  HostSnapshot h;
  h.ts_ns = 1000000000000ULL;
  h.total = { 7000, 0, 3000, 90000, 1000, 500, 500, 0 };
  h.load = { 1.5, 1.2, 1.0, 4, 300 };
  h.mem = { 33500000, 3000000, 1500000, 400000, 2000000, 4194304, 4194299, 1200000 };
  h.vm = { 10000, 5, 3, 1, 200000, 100000 };
  h.psi = { 5.0, 4.0, 3.0, 2.0, 1.5, 1.0, 8.0, 6.0, 4.0 };
  for (int i = 0; i < 8; i++)
    h.cpus.push_back({ 700, 0, 300, 9000, 100, 50, 50, 0 });
  h.disks.push_back({ 8, 0, {'s','d','a'}, 1000, 2000, 10000, 20000, 1000, 500, 400 });
  ProcessRow p;
  p.pid = 7; p.tgid = 7; p.state = 0; p.start_time = 1;
  p.utime = 50000000; p.stime = 10000000; p.nvcsw = 10; p.nivcsw = 5;
  p.total_vm = 1000000; p.rss_kb = 80000;
  snprintf(p.comm, sizeof(p.comm), "matmul");
  h.procs.push_back(p);
  w.WriteHostRow(h);
  // second tick with higher cumulative counters (drives delta-based metrics)
  HostSnapshot h2 = h;
  h2.ts_ns = 1001000000000ULL;
  h2.total = { 8000, 0, 4000, 95100, 1100, 600, 600, 0 };
  h2.load = { 1.8, 1.4, 1.1, 5, 310 };
  h2.vm.pgfault = 10300; h2.vm.pgmajfault = 6;
  h2.psi.cpu10 = 6.0;
  for (auto& c : h2.cpus) { c.user += 100; c.system += 100; c.idle += 600; }
  h2.disks[0] = { 8, 0, {'s','d','a'}, 2000, 4000, 30000, 60000, 2200, 1200, 900 };
  h2.procs[0].utime = 80000000; h2.procs[0].stime = 15000000;
  h2.procs[0].rss_kb = 82000;
  w.WriteHostRow(h2);
  // third tick
  HostSnapshot h3 = h2;
  h3.ts_ns = 1002000000000ULL;
  h3.total = { 9000, 0, 5000, 100300, 1200, 700, 700, 0 };
  h3.load = { 2.0, 1.5, 1.2, 6, 320 };
  h3.vm.pgfault = 10600; h3.vm.pswpin = 4;
  h3.disks[0] = { 8, 0, {'s','d','a'}, 3000, 6000, 50000, 100000, 3500, 1900, 1400 };
  h3.procs[0].utime = 110000000; h3.procs[0].stime = 20000000; h3.procs[0].rss_kb = 84000;
  for (auto& c : h3.cpus) { c.user += 100; c.system += 100; c.idle += 700; }
  w.WriteHostRow(h3);

  // anomaly features (anomaly + anomaly_tid)
  nlohmann::json f = {
    {"v", 1}, {"seq", 0}, {"ts_ns", 1000000000000ULL},
    {"ebpf", {
      {"on_cpu_ns_total", 600000000ULL}, {"switch_total", 300},
      {"io_ops_total", 150}, {"io_bytes_total", 9000},
      {"faults_total", 60}, {"lock_waits_total", 15},
      {"per_tid", nlohmann::json::array({
        {{"tid", 100}, {"on_cpu_ns", 400000000ULL}, {"nr_sw_vol", 200},
         {"nr_sw_invol", 5}, {"io_ops", 100}, {"io_bytes", 6000},
         {"pf_minor", 40}, {"pf_major", 0}, {"lock_waits", 10}, {"lock_lat_ns", 20000}},
      })}
    }}
  };
  w.WriteAnomalyFeatures(f);

  // targets join (with tgid) + leave (no tgid)
  w.WriteTargetsEvent({{"v",1},{"ts_ns",1000000000000ULL},{"action","join"},
                       {"tgid",7},{"tid",100},{"comm","matmul"},{"score",0.9},{"rank",1}});
  w.WriteTargetsEvent({{"v",1},{"ts_ns",1005000000000ULL},{"action","leave"},
                       {"tid",100},{"comm","matmul"},{"rank",1}});

  // memory + oom + io devices
  w.WriteMemoryEvent({{"v",1},{"ts_ns",1000000000000ULL},{"kswapd_active",1},
                      {"direct_reclaim",10},{"nr_reclaimed",100}});
  w.WriteMemoryEvent({{"v",1},{"ts_ns",1000000000000ULL},{"pid",99},{"comm","java"}});
  w.WriteIoDevice({{"v",1},{"ts_ns",1000000000000ULL},{"dev",0x0800},{"ops",50},
                   {"bytes",50000},{"lat_sum",1000000}});

  // bpf stats + proc overhead
  BpfStatsSnapshot bs;
  bs.ts_ns = 1000000000000ULL; bs.interval_ns = 1000000000ULL; bs.stats_enabled = true;
  bs.progs.push_back({"on_switch", 1, 1000, 5000000});
  w.WriteBpfStats(bs);
  ProcOverhead po;
  po.ts_ns = 1000000000000ULL; po.utime_ns = 300000000ULL; po.stime_ns = 100000000ULL;
  po.nvcsw = 100; po.nivcsw = 50; po.minflt = 1000; po.majflt = 5;
  po.rss_kb = 50000; po.vmhwm_kb = 60000;
  w.WriteProcOverhead(po);

  // deep episode + series + gap + folded + hotspots
  if (!w.OpenDeep(1)) { fprintf(stderr, "OpenDeep failed\n"); return 1; }
  w.BeginBatch();
  CanonicalSnapshot s;
  s.ts_ns = 1000000000000ULL; s.tgid = 7; s.tid = 100;
  snprintf(s.comm, sizeof(s.comm), "matmul");
  s.on_cpu_ns = 400000000ULL; s.nr_sw_vol = 200; s.nr_sw_invol = 5;
  s.io_ops = 100; s.io_bytes = 6000; s.io_hist[2] = 3;
  s.pf_minor = 40; s.pf_major = 0; s.lock_waits = 10; s.lock_lat_ns = 20000;
  s.syscall_count = 500; s.syscall_lat_ns = 250000; s.futex_waits = 30;
  s.futex_lat_ns = 6000; s.runq_wait_count = 4; s.runq_wait_ns = 100;
  w.WritePreSeries(s);
  CanonicalSnapshot s2 = s; s2.ts_ns = 1000020000000ULL;
  w.WritePostSeries(s2);
  w.WritePostSeriesGap(1000, 1500);
  w.WriteFoldedLine("on_cpu",
      "p:7/matmul;t:100/matmul;start_kernel;__x64_sys_futex;/lib/x86_64-linux-gnu/libc.so.6+0x12a", 400);
  w.WriteFoldedLine("off_cpu", "t:100/matmul;schedule;io_schedule", 5000000);
  w.WriteDeepSyscall(100, 202, 400, 50.0f, 10.0f, 500.0f);   // 202 = futex
  w.WriteDeepLock(0xffff8880ULL, 100, 5000000, "mutex_lock+0x10");
  w.WriteDeepRunq(100, 200, 50.0f, 20.0f, 800.0f);
  w.WriteDeepIoFile(2048, 12345, "/opt/matmul/data.bin", 1048576, 200);
  w.CommitBatch();
  w.WriteMeta({{"v",1},{"anomaly_start_ts",1000000000000ULL},
               {"anomaly_end_ts",1000075000000ULL},{"deep_ordinal",1}});
  w.WriteSummary("{\n  \"v\": 1\n}\n");
  w.CloseDeep();

  w.Close();
  printf("session dir: %s\n", w.session_dir().c_str());
  return 0;
}
