/* eTrace-Diag viz — SQL extraction + metric registry + transforms (pure, no DOM).
 * Node-testable: everything hangs off window.V / globalThis.V.
 */
(function (global) {
  'use strict';
  const V = global.V = global.V || {};

  // scale registry: scale -> { unit, lock0, lock100 }
  V.SCALES = {
    pct:   { unit: '%',    lock0: true,  lock100: true },
    count: { unit: '个',   lock0: true,  lock100: false },
    rate:  { unit: '次/s', lock0: true,  lock100: false },
    mb:    { unit: 'MB',   lock0: true,  lock100: false },
    mbps:  { unit: 'MB/s', lock0: true,  lock100: false },
    ms:    { unit: 'ms',   lock0: true,  lock100: false },
    load:  { unit: 'load', lock0: false, lock100: false },
    bool:  { unit: '0/1',  lock0: true,  lock100: false },
  };

  // ---- metric registry. Each entry: {mid,label,table,kind,scale,expr(prev,cur,{s,ns})}
  // kind: 'gauge' (raw value, emit every row) | 'counter' (delta) | 'step' (raw, step kind)
  const METRICS = [];
  function reg(m) { METRICS.push(m); return m; }

  // CPU delta helpers
  const cpuD = (p, c) => ({
    user: c.cu_user - p.cu_user, nice: c.cu_nice - p.cu_nice, sys: c.cu_sys - p.cu_sys,
    idle: c.cu_idle - p.cu_idle, iowait: c.cu_iowait - p.cu_iowait,
    irq: c.cu_irq - p.cu_irq, softirq: c.cu_softirq - p.cu_softirq, steal: c.cu_steal - p.cu_steal,
  });
  const allSum = (d) => d.user + d.nice + d.sys + d.idle + d.iowait + d.irq + d.softirq + d.steal;
  const cpuPct = (p, c, pick) => { const A = allSum(cpuD(p, c)); return A ? 100 * pick(cpuD(p, c)) / A : null; };

  const CPU_MONO = ['cu_user', 'cu_nice', 'cu_sys', 'cu_idle', 'cu_iowait', 'cu_irq', 'cu_softirq', 'cu_steal'];
  reg({ mid: 'host.cpu.usage_pct', label: 'CPU 利用率', table: 'host', scale: 'pct', kind: 'counter', mono: CPU_MONO,
    expr(p, c) { return cpuPct(p, c, (d) => d.user + d.nice + d.sys + d.irq + d.softirq + d.steal + d.iowait); } });
  reg({ mid: 'host.cpu.user_pct', label: '用户态', table: 'host', scale: 'pct', kind: 'counter', mono: CPU_MONO,
    expr(p, c) { return cpuPct(p, c, (d) => d.user + d.nice); } });
  reg({ mid: 'host.cpu.sys_pct', label: '内核态', table: 'host', scale: 'pct', kind: 'counter', mono: CPU_MONO,
    expr(p, c) { return cpuPct(p, c, (d) => d.sys); } });
  reg({ mid: 'host.cpu.iowait_pct', label: 'IO 等待', table: 'host', scale: 'pct', kind: 'counter', mono: CPU_MONO,
    expr(p, c) { return cpuPct(p, c, (d) => d.iowait); } });
  reg({ mid: 'host.cpu.irq_pct', label: '中断', table: 'host', scale: 'pct', kind: 'counter', mono: CPU_MONO,
    expr(p, c) { return cpuPct(p, c, (d) => d.irq + d.softirq); } });

  reg({ mid: 'host.load.load1', label: '负载1', table: 'host', scale: 'load', kind: 'gauge', expr(p, c) { return c.load1; } });
  reg({ mid: 'host.load.load5', label: '负载5', table: 'host', scale: 'load', kind: 'gauge', expr(p, c) { return c.load5; } });
  reg({ mid: 'host.load.load15', label: '负载15', table: 'host', scale: 'load', kind: 'gauge', expr(p, c) { return c.load15; } });
  reg({ mid: 'host.load.nr_running', label: '运行队列', table: 'host', scale: 'count', kind: 'gauge', expr(p, c) { return c.nr_running; } });
  reg({ mid: 'host.load.nr_threads', label: '线程总数', table: 'host', scale: 'count', kind: 'gauge', expr(p, c) { return c.nr_threads; } });

  reg({ mid: 'host.mem.used_pct', label: '内存占用', table: 'host', scale: 'pct', kind: 'gauge',
    expr(p, c) { return c.mem_total_kb ? 100 * (c.mem_total_kb - c.mem_avail_kb) / c.mem_total_kb : null; } });
  reg({ mid: 'host.mem.cached_mb', label: '页缓存', table: 'host', scale: 'mb', kind: 'gauge', expr(p, c) { return c.cached_kb / 1024; } });
  reg({ mid: 'host.mem.buffers_mb', label: '缓冲', table: 'host', scale: 'mb', kind: 'gauge', expr(p, c) { return c.buffers_kb / 1024; } });
  reg({ mid: 'host.mem.anon_mb', label: '匿名页', table: 'host', scale: 'mb', kind: 'gauge', expr(p, c) { return c.anon_pages_kb / 1024; } });
  reg({ mid: 'host.mem.avail_mb', label: '可用内存', table: 'host', scale: 'mb', kind: 'gauge', expr(p, c) { return c.mem_avail_kb / 1024; } });
  reg({ mid: 'host.mem.swap_used_pct', label: 'Swap 占用', table: 'host', scale: 'pct', kind: 'gauge',
    expr(p, c) { return c.swap_total_kb ? 100 * (c.swap_total_kb - c.swap_free_kb) / c.swap_total_kb : null; } });

  reg({ mid: 'host.vm.pgfault_s', label: '缺页', table: 'host', scale: 'rate', kind: 'counter', mono: ['vm_pgfault'],
    expr(p, c, t) { return t.s ? (c.vm_pgfault - p.vm_pgfault) / t.s : null; } });
  reg({ mid: 'host.vm.pgmajfault_s', label: '主缺页', table: 'host', scale: 'rate', kind: 'counter', mono: ['vm_pgmajfault'],
    expr(p, c, t) { return t.s ? (c.vm_pgmajfault - p.vm_pgmajfault) / t.s : null; } });
  reg({ mid: 'host.vm.pswpin_s', label: '换入', table: 'host', scale: 'rate', kind: 'counter', mono: ['vm_pswpin'],
    expr(p, c, t) { return t.s ? (c.vm_pswpin - p.vm_pswpin) / t.s : null; } });
  reg({ mid: 'host.vm.pswpout_s', label: '换出', table: 'host', scale: 'rate', kind: 'counter', mono: ['vm_pswpout'],
    expr(p, c, t) { return t.s ? (c.vm_pswpout - p.vm_pswpout) / t.s : null; } });

  ['cpu', 'io', 'mem'].forEach((grp) => {
    ['avg10', 'avg60', 'avg300'].forEach((w) => {
      reg({ mid: `host.psi.${grp}.${w}`, label: `PSI ${grp} ${w}`, table: 'host', scale: 'pct', kind: 'gauge',
        expr(p, c) { return c[`psi_${grp}${w}`]; } });
    });
  });

  // ---- anomaly totals (ebpf.*) ----
  reg({ mid: 'ebpf.busy_pct', label: '目标线程总在核占比', table: 'anomaly', scale: 'pct', kind: 'counter', mono: ['on_cpu_ns_total'],
    expr(p, c, t) { return t.ns ? 100 * (c.on_cpu_ns_total - p.on_cpu_ns_total) / t.ns : null; } });
  reg({ mid: 'ebpf.switches_s', label: '切换', table: 'anomaly', scale: 'rate', kind: 'counter', mono: ['switch_total'],
    expr(p, c, t) { return t.s ? (c.switch_total - p.switch_total) / t.s : null; } });
  reg({ mid: 'ebpf.faults_s', label: '缺页', table: 'anomaly', scale: 'rate', kind: 'counter', mono: ['faults_total'],
    expr(p, c, t) { return t.s ? (c.faults_total - p.faults_total) / t.s : null; } });
  reg({ mid: 'ebpf.io_ops_s', label: 'IOPS', table: 'anomaly', scale: 'rate', kind: 'counter', mono: ['io_ops_total'],
    expr(p, c, t) { return t.s ? (c.io_ops_total - p.io_ops_total) / t.s : null; } });
  reg({ mid: 'ebpf.io_mbs', label: 'IO 吞吐', table: 'anomaly', scale: 'mbps', kind: 'counter', mono: ['io_bytes_total'],
    expr(p, c, t) { return t.s ? (c.io_bytes_total - p.io_bytes_total) / 1e6 / t.s : null; } });
  reg({ mid: 'ebpf.lock_waits_s', label: '锁等待', table: 'anomaly', scale: 'rate', kind: 'counter', mono: ['lock_waits_total'],
    expr(p, c, t) { return t.s ? (c.lock_waits_total - p.lock_waits_total) / t.s : null; } });

  // ---- proc_overhead (ovh) ----
  reg({ mid: 'ovh.cpu_pct', label: '采集器CPU', table: 'proc_overhead', scale: 'pct', kind: 'counter',
    expr(p, c, t) { return t.ns ? 100 * ((c.utime_ns + c.stime_ns) - (p.utime_ns + p.stime_ns)) / t.ns : null; } });
  reg({ mid: 'ovh.rss_mb', label: '采集器RSS', table: 'proc_overhead', scale: 'mb', kind: 'gauge', expr(p, c) { return c.rss_kb / 1024; } });
  reg({ mid: 'ovh.vmhwm_mb', label: '采集器峰值', table: 'proc_overhead', scale: 'mb', kind: 'gauge', expr(p, c) { return c.vmhwm_kb / 1024; } });
  reg({ mid: 'ovh.minflt_s', label: '采集器次缺页', table: 'proc_overhead', scale: 'rate', kind: 'counter', mono: ['minflt'],
    expr(p, c, t) { return t.s ? (c.minflt - p.minflt) / t.s : null; } });
  reg({ mid: 'ovh.majflt_s', label: '采集器主缺页', table: 'proc_overhead', scale: 'rate', kind: 'counter', mono: ['majflt'],
    expr(p, c, t) { return t.s ? (c.majflt - p.majflt) / t.s : null; } });
  reg({ mid: 'ovh.vcsw_s', label: '采集器自愿切换', table: 'proc_overhead', scale: 'rate', kind: 'counter', mono: ['nvcsw'],
    expr(p, c, t) { return t.s ? (c.nvcsw - p.nvcsw) / t.s : null; } });
  reg({ mid: 'ovh.ivcsw_s', label: '采集器非自愿切换', table: 'proc_overhead', scale: 'rate', kind: 'counter', mono: ['nivcsw'],
    expr(p, c, t) { return t.s ? (c.nivcsw - p.nivcsw) / t.s : null; } });

  // ---- memory_events ----
  reg({ mid: 'memv.kswapd', label: 'kswapd 活动', table: 'memory_events', scale: 'bool', kind: 'step',
    expr(p, c) { return c.kswapd_active; } });
  reg({ mid: 'memv.direct_reclaim_s', label: '直接回收', table: 'memory_events', scale: 'rate', kind: 'counter', mono: ['direct_reclaim'],
    expr(p, c, t) { return t.s ? (c.direct_reclaim - p.direct_reclaim) / t.s : null; } });
  reg({ mid: 'memv.nr_reclaimed_s', label: '回收页速率', table: 'memory_events', scale: 'rate', kind: 'counter', mono: ['nr_reclaimed'],
    expr(p, c, t) { return t.s ? (c.nr_reclaimed - p.nr_reclaimed) / t.s : null; } });

  // DEEP per-thread trend metrics (computed from raw cumulative columns at render).
  V.DEEP_METRICS = [
    { id: 'cpu_pct', label: '在核占比%', unit: '%',
      expr(d, t) { return t.ts ? 100 * d.on_cpu_ns / t.ts : null; } },
    { id: 'switch_s', label: '切换/s', unit: '次/s',
      expr(d, t) { return t.s ? (d.nr_sw_vol + d.nr_sw_invol) / t.s : null; } },
    { id: 'io_ops_s', label: 'IO 速率', unit: '次/s',
      expr(d, t) { return t.s ? d.io_ops / t.s : null; } },
    { id: 'io_mbs', label: 'IO 吞吐', unit: 'MB/s',
      expr(d, t) { return t.s ? d.io_bytes / 1e6 / t.s : null; } },
    { id: 'fault_s', label: '缺页/s', unit: '次/s',
      expr(d, t) { return t.s ? d.pf_minor / t.s : null; } },
    { id: 'majpf_s', label: '主缺页/s', unit: '次/s',
      expr(d, t) { return t.s ? d.pf_major / t.s : null; } },
    { id: 'lock_s', label: '锁等待/s', unit: '次/s',
      expr(d, t) { return t.s ? d.lock_waits / t.s : null; } },
    { id: 'lock_avg_ms', label: '锁均时ms', unit: 'ms',
      expr(d) { return d.lock_waits ? d.lock_lat_ns / d.lock_waits / 1e6 : null; } },
    { id: 'sys_s', label: '系统调用/s', unit: '次/s',
      expr(d, t) { return t.s ? d.syscall_count / t.s : null; } },
    { id: 'sys_avg_ms', label: '系统调用均时ms', unit: 'ms',
      expr(d) { return d.syscall_count ? d.syscall_lat_ns / d.syscall_count / 1e6 : null; } },
    { id: 'futex_s', label: 'futex/s', unit: '次/s',
      expr(d, t) { return t.s ? d.futex_waits / t.s : null; } },
    { id: 'futex_avg_ms', label: 'futex均时ms', unit: 'ms',
      expr(d) { return d.futex_waits ? d.futex_lat_ns / d.futex_waits / 1e6 : null; } },
    { id: 'runq_s', label: '调度延迟/s', unit: '次/s',
      expr(d, t) { return t.s ? d.runq_wait_count / t.s : null; } },
    { id: 'runq_avg_ms', label: '调度均时ms', unit: 'ms',
      expr(d) { return d.runq_wait_count ? d.runq_wait_ns / d.runq_wait_count / 1e6 : null; } },
  ];

  V.METRICS = METRICS;
  // 由单位推导量纲名（决定 TChart 锁轴与刻度），新增指标无需手填
  const UNIT2SCALE = { '%': 'pct', '次/s': 'rate', 'MB/s': 'mbps', 'ms': 'ms' };
  for (const m of V.DEEP_METRICS) m.scaleName = UNIT2SCALE[m.unit] || 'count';
  const byMid = new Map(METRICS.map((m) => [m.mid, m]));

  // scale lookup for any (possibly parametric) mid
  function scaleOf(mid) {
    if (byMid.has(mid)) return byMid.get(mid).scale;
    if (mid.startsWith('host.cpu.core.')) return 'pct';
    if (mid.startsWith('host.disk.')) {
      if (mid.endsWith('_mbs')) return 'mbps';
      if (mid.endsWith('util_pct')) return 'pct';
      if (mid.endsWith('_await_ms')) return 'ms';
    }
    if (mid.startsWith('bpf.prog.')) return mid.endsWith('runs_s') ? 'rate' : 'ms';
    if (mid.startsWith('iodev.')) return mid.endsWith('ops_s') ? 'rate' : mid.endsWith('mbs') ? 'mbps' : 'ms';
    if (mid.startsWith('host.proc.')) return mid.endsWith('cpu_pct') ? 'pct' : 'mb';
    if (mid.startsWith('ebpf.tid.')) {
      if (mid.includes('cpu_pct')) return 'pct';
      if (mid.includes('io_mbs')) return 'mbps';
      if (mid.includes('lock_avg')) return 'ms';
      return 'rate';
    }
    return 'count';
  }

  // ------------------------------------------------------------------
  // Session extraction -> { store, enums, events, bands, t0 }
  // store: Map<mid, {x:Array,y:Array,unit,scale,label}>
  // ------------------------------------------------------------------
  V.extract = function (db) {
    const t0 = V.db.scalar(db, 'SELECT MIN(ts_ns) FROM host')
            ?? V.db.scalar(db, 'SELECT MIN(ts_ns) FROM anomaly') ?? 0;
    const store = new Map();
    const enums = { cores: [], disks: [], procs: [], tids: [], bpfProgs: [], iodevs: [] };
    const tidRaw = new Map();   // 本次 extract 的 per-tid 原始序列（会话内局部，避免跨会话污染）
    const events = [];
    const bands = [];

    function series(mid, scale, label) {
      let s = store.get(mid);
      if (!s) {
        s = { mid, x: [], y: [], scale, unit: V.SCALES[scale].unit, label };
        store.set(mid, s);
      }
      return s;
    }
    const push = (mid, scale, label, x, y) => {
      if (y == null || !isFinite(y)) return;
      const s = series(mid, scale, label);
      s.x.push(x); s.y.push(y);
    };

    // ---- host (gauge on every row; counter on consecutive rows) ----
    let prev = null;
    V.db.step(db,
      `SELECT ts_ns,cu_user,cu_nice,cu_sys,cu_idle,cu_iowait,cu_irq,cu_softirq,cu_steal,` +
      `load1,load5,load15,nr_running,nr_threads,mem_total_kb,mem_avail_kb,mem_free_kb,` +
      `buffers_kb,cached_kb,swap_total_kb,swap_free_kb,anon_pages_kb,vm_pgfault,vm_pgmajfault,` +
      `vm_pswpin,vm_pswpout,vm_free_pages,vm_anon_pages,psi_cpu10,psi_cpu60,psi_cpu300,` +
      `psi_io10,psi_io60,psi_io300,psi_mem10,psi_mem60,psi_mem300 FROM host ORDER BY ts_ns`,
      null, (r) => {
        const x = (r.ts_ns - t0) / 1e9;
        for (const m of METRICS) {
          if (m.table !== 'host' || m.kind === 'counter') continue;
          const v = m.expr(prev, r, { s: 0, ns: 0 });
          if (v == null) continue;
          push(m.mid, m.scale, m.label, x, v);
        }
        if (prev) {
          const t = { s: (r.ts_ns - prev.ts_ns) / 1e9, ns: r.ts_ns - prev.ts_ns };
          for (const m of METRICS) {
            if (m.table !== 'host' || m.kind !== 'counter') continue;
            if (m.mono && m.mono.some((f) => r[f] < prev[f])) continue; // counter wrap -> break point
            const v = m.expr(prev, r, t);
            if (v == null) continue;
            push(m.mid, m.scale, m.label, x, v);
          }
        }
        prev = r;
      });

    // ---- host_cpu (parametric per-core) ----
    const corePrev = new Map();
    V.db.step(db, `SELECT ts_ns,cpu_idx,usr,nice,sys,idle,iowait,irq,softirq,steal ` +
      `FROM host_cpu ORDER BY ts_ns,cpu_idx`, null, (r) => {
        enums.cores.push(r.cpu_idx);
        const prev = corePrev.get(r.cpu_idx);
        const x = (r.ts_ns - t0) / 1e9;
        if (prev) {
          const A = (r.usr - prev.usr) + (r.nice - prev.nice) + (r.sys - prev.sys) +
                    (r.idle - prev.idle) + (r.iowait - prev.iowait) + (r.irq - prev.irq) +
                    (r.softirq - prev.softirq) + (r.steal - prev.steal);
          if (A > 0) push(`host.cpu.core.${r.cpu_idx}.usage_pct`, 'pct', `核${r.cpu_idx}利用率`, x,
                      100 * (1 - (r.idle - prev.idle) / A));
        }
        corePrev.set(r.cpu_idx, r);
      });
    enums.cores = [...new Set(enums.cores)];

    // ---- host_disk (parametric per-name) ----
    const diskPrev = new Map();
    V.db.step(db, `SELECT ts_ns,name,major,minor,reads_completed,writes_completed,` +
      `sectors_read,sectors_written,io_ticks_ms,read_ticks_ms,write_ticks_ms ` +
      `FROM host_disk ORDER BY ts_ns,name`, null, (r) => {
        enums.disks.push(r.name);
        const prev = diskPrev.get(r.name);
        const x = (r.ts_ns - t0) / 1e9;
        if (prev) {
          const t = (r.ts_ns - prev.ts_ns) / 1e9;
          if (t) {
            const sr = r.sectors_read - prev.sectors_read;
            const sw = r.sectors_written - prev.sectors_written;
            const it = r.io_ticks_ms - prev.io_ticks_ms;
            if (sr >= 0) push(`host.disk.${r.name}.read_mbs`, 'mbps', `盘读 ${r.name}`, x, sr * 512 / 1e6 / t);
            if (sw >= 0) push(`host.disk.${r.name}.write_mbs`, 'mbps', `盘写 ${r.name}`, x, sw * 512 / 1e6 / t);
            if (it >= 0) push(`host.disk.${r.name}.util_pct`, 'pct', `盘繁忙 ${r.name}`, x, 100 * it / 1000 / t);
            const dr = r.reads_completed - prev.reads_completed;
            const dw = r.writes_completed - prev.writes_completed;
            if (dr > 0 && r.read_ticks_ms - prev.read_ticks_ms >= 0)
              push(`host.disk.${r.name}.read_await_ms`, 'ms', `盘读时延 ${r.name}`, x,
                   (r.read_ticks_ms - prev.read_ticks_ms) / dr);
            if (dw > 0 && r.write_ticks_ms - prev.write_ticks_ms >= 0)
              push(`host.disk.${r.name}.write_await_ms`, 'ms', `盘写时延 ${r.name}`, x,
                   (r.write_ticks_ms - prev.write_ticks_ms) / dw);
          }
        }
        diskPrev.set(r.name, r);
      });
    enums.disks = [...new Set(enums.disks)];

    // ---- host_proc (pid dimension family; keep raw per pid) ----
    const procPrev = new Map();
    const procRaw = new Map(); // pid -> {pid, comm, tgid, x:[], cpu:[], rss:[]}
    V.db.step(db, `SELECT ts_ns,pid,tgid,comm,utime,stime,nvcsw,nivcsw,rss_kb ` +
      `FROM host_proc ORDER BY ts_ns,pid`, null, (r) => {
        const pid = r.pid, g = r.tgid || r.pid;
        if (!enums.procs.some((p) => p.pid === g)) enums.procs.push({ pid: g, comm: r.comm });
        let raw = procRaw.get(pid);
        if (!raw) { raw = { pid, comm: r.comm, tgid: g, x: [], cpu: [], rss: [] }; procRaw.set(pid, raw); }
        const x = (r.ts_ns - t0) / 1e9;
        raw.x.push(x);
        const p = procPrev.get(pid);
        if (p) {
          const dt = (r.ts_ns - p.ts_ns) / 1e9;
          const du = r.utime - p.utime, ds = r.stime - p.stime;
          if (dt && du >= 0 && ds >= 0) raw.cpu.push([x, 100 * (du + ds) / dt / 1e9]);
        }
        raw.rss.push([x, r.rss_kb / 1024]);
        procPrev.set(pid, r);
      });
    for (const raw of procRaw.values()) {
      const g = raw.tgid;
      pushSeries(store, `host.proc.${g}.cpu_pct`, 'pct', `进程CPU ${raw.comm}`, raw.cpu);
      pushSeries(store, `host.proc.${g}.rss_mb`, 'mb', `进程RSS ${raw.comm}`, raw.rss);
    }

    // ---- anomaly totals ----
    let ap = null;
    V.db.step(db, `SELECT ts_ns,on_cpu_ns_total,switch_total,io_ops_total,io_bytes_total,` +
      `faults_total,lock_waits_total FROM anomaly ORDER BY ts_ns`, null, (r) => {
        const x = (r.ts_ns - t0) / 1e9;
        if (ap) {
          const t = { s: (r.ts_ns - ap.ts_ns) / 1e9, ns: r.ts_ns - ap.ts_ns };
          for (const mid of ['ebpf.busy_pct', 'ebpf.switches_s', 'ebpf.faults_s',
                             'ebpf.io_ops_s', 'ebpf.io_mbs', 'ebpf.lock_waits_s']) {
            const m = byMid.get(mid);
            const f = m.mono[0];
            if (r[f] < ap[f]) continue;
            push(mid, m.scale, m.label, x, m.expr(ap, r, t));
          }
        }
        ap = r;
      });

    // ---- anomaly_tid (tid dimension family; keep raw cumulative per tid) ----
    V.db.step(db, `SELECT a.ts_ns,a.tid,a.comm,COALESCE(m.tgid,0) AS tgid,a.on_cpu_ns,` +
      `a.nr_sw_vol,a.nr_sw_invol,a.io_ops,a.io_bytes,a.pf_minor,a.pf_major,` +
      `a.lock_waits,a.lock_lat_ns FROM anomaly_tid a LEFT JOIN ` +
      `(SELECT tid,MAX(tgid) AS tgid FROM targets_log WHERE action='join' GROUP BY tid) m ` +
      `ON m.tid=a.tid ORDER BY a.ts_ns,a.tid`, null, (r) => {
        if (!enums.tids.some((t) => t.tid === r.tid)) enums.tids.push({ tid: r.tid, comm: r.comm, tgid: r.tgid });
        let ts = tidRaw.get(r.tid);
        if (!ts) {
          ts = { tid: r.tid, comm: r.comm, tgid: r.tgid, x: [],
                 raw: { on_cpu_ns: [], nr_sw_vol: [], nr_sw_invol: [], io_ops: [], io_bytes: [],
                        pf_minor: [], pf_major: [], lock_waits: [], lock_lat_ns: [] } };
          tidRaw.set(r.tid, ts);
        }
        ts.x.push((r.ts_ns - t0) / 1e9);
        for (const k of Object.keys(ts.raw)) ts.raw[k].push(r[k] || 0);
      });

    // ---- bpf_stats (parametric per prog) ----
    const bpfPrev = new Map();
    V.db.step(db, `SELECT ts_ns,prog_name,run_cnt,run_time_ns FROM bpf_stats ` +
      `ORDER BY ts_ns,prog_name`, null, (r) => {
        enums.bpfProgs.push(r.prog_name);
        const prev = bpfPrev.get(r.prog_name);
        const x = (r.ts_ns - t0) / 1e9;
        if (prev) {
          const dt = (r.ts_ns - prev.ts_ns) / 1e9;
          const dc = r.run_cnt - prev.run_cnt, dtm = r.run_time_ns - prev.run_time_ns;
          if (dt) {
            if (dc >= 0) push(`bpf.prog.${r.prog_name}.runs_s`, 'rate', `程序调用 ${r.prog_name}`, x, dc / dt);
            if (dtm >= 0) push(`bpf.prog.${r.prog_name}.ms_per_s`, 'ms', `内核耗时 ${r.prog_name}`, x, dtm / dt / 1e6);
          }
        }
        bpfPrev.set(r.prog_name, r);
      });
    enums.bpfProgs = [...new Set(enums.bpfProgs)];

    // ---- io_devices (dev -> disk name best-effort) ----
    const mm = new Map();
    V.db.step(db, `SELECT DISTINCT name,major,minor FROM host_disk`, null, (r) =>
      mm.set(r.major + ':' + r.minor, r.name));
    const decodeDev = (dev) => ({
      major: (Number(dev) >> 8) & 0xfff,
      minor: (Number(dev) & 0xff) | ((Number(dev) >> 12) & 0xfff00),
    });
    const iodevPrev = new Map();
    V.db.step(db, `SELECT ts_ns,dev,ops,bytes,lat_sum FROM io_devices ORDER BY ts_ns,dev`,
      null, (r) => {
        const { major, minor } = decodeDev(r.dev);
        const name = mm.get(major + ':' + minor);
        const label = name || '0x' + (Number(r.dev) >>> 0).toString(16);
        if (!enums.iodevs.includes(label)) enums.iodevs.push(label);
        const prev = iodevPrev.get(label);
        const x = (r.ts_ns - t0) / 1e9;
        if (prev) {
          const dt = (r.ts_ns - prev.ts_ns) / 1e9;
          const dop = r.ops - prev.ops, dbts = r.bytes - prev.bytes, dlat = r.lat_sum - prev.lat_sum;
          if (dt) {
            if (dop >= 0) push(`iodev.${label}.ops_s`, 'rate', `设备IOPS ${label}`, x, dop / dt);
            if (dbts >= 0) push(`iodev.${label}.mbs`, 'mbps', `设备吞吐 ${label}`, x, dbts / 1e6 / dt);
            if (dop > 0 && dlat >= 0) push(`iodev.${label}.await_ms`, 'ms', `设备时延 ${label}`, x, dlat / dop / 1e6);
          }
        }
        iodevPrev.set(label, r);
      });

    // ---- memory_events + oom_events ----
    let mp = null;
    V.db.step(db, `SELECT ts_ns,kswapd_active,direct_reclaim,nr_reclaimed ` +
      `FROM memory_events ORDER BY ts_ns`, null, (r) => {
        const x = (r.ts_ns - t0) / 1e9;
        push('memv.kswapd', 'bool', 'kswapd 活动', x, r.kswapd_active);
        if (mp) {
          const t = { s: (r.ts_ns - mp.ts_ns) / 1e9, ns: r.ts_ns - mp.ts_ns };
          if (r.direct_reclaim >= mp.direct_reclaim)
            push('memv.direct_reclaim_s', 'rate', '直接回收', x, (r.direct_reclaim - mp.direct_reclaim) / t.s);
          if (r.nr_reclaimed >= mp.nr_reclaimed)
            push('memv.nr_reclaimed_s', 'rate', '回收页速率', x, (r.nr_reclaimed - mp.nr_reclaimed) / t.s);
        }
        if (r.kswapd_active) events.push({ x, kind: 'kswapd', label: 'kswapd 活动' });
        mp = r;
      });
    V.db.step(db, `SELECT ts_ns,pid,comm FROM oom_events ORDER BY ts_ns`, null, (r) =>
      events.push({ x: (r.ts_ns - t0) / 1e9, kind: 'oom',
        label: 'OOM ' + (r.comm || '') + '(' + r.pid + ')' }));

    // ---- targets events ----
    V.db.step(db, `SELECT ts_ns,action,tgid,tid,comm FROM targets_log ORDER BY ts_ns`,
      null, (r) => {
        const x = (r.ts_ns - t0) / 1e9;
        const mark = r.action === 'leave' ? 'leave' : 'join';
        events.push({ x, kind: mark,
          label: (mark === 'join' ? '+' : '-') + (r.comm || '') + '(' + r.tid + ')' });
      });

    // ---- deep episodes -> DEEP bands ----
    const maxTs = V.db.scalar(db, 'SELECT MAX(ts_ns) FROM host') ?? t0;
    for (const ep of V.db.query(db, 'SELECT ordinal,meta_json FROM deep_episodes ORDER BY ordinal')) {
      let start = null, end = null;
      if (ep.meta_json) {
        try {
          const m = JSON.parse(ep.meta_json);
          start = m.anomaly_start_ts; end = m.anomaly_end_ts;
        } catch (e) { /* ignore */ }
      }
      if (start != null) {
        bands.push({ x0: (start - t0) / 1e9,
                     x1: (end ? end - t0 : maxTs - t0) / 1e9, label: 'DEEP#' + ep.ordinal });
      }
    }

    return { store, enums, events, bands, t0, tidRaw };
  };

  // ---- 5.4 grouped aggregation over raw per-tid cumulative series ----
  // tidSeries: array of {tid, comm, tgid, x:[...], raw:{col:[...]}}
  // mode: 'tid' | 'pid' | 'top'
  // metricExpr: (Δobj, {s, ts}) -> value|null   (ts = ns delta)
  V.aggregate = function (tidSeries, { mode, sel }, metricExpr) {
    const first = tidSeries[0];
    if (!first) return { x: [], y: [], lines: [] };
    const cols = Object.keys(first.raw);
    // cumulative counters must never decrease; a wrap is a break point (null).
    const deltas = (a, b) => {
      const d = {}; let wrapped = false;
      cols.forEach((c) => { d[c] = b[c] - a[c]; if (d[c] < 0) wrapped = true; });
      return wrapped ? null : d;
    };

    if (mode === 'pid' || mode === 'top') {
      let pids;
      if (mode === 'top') {
        const n = (sel && sel.length) ? sel[0] : 5;
        const rankKey = cols.includes('on_cpu_ns') ? 'on_cpu_ns' : 'io_ops';
        const ranked = tidSeries.map((t) => {
          let total = 0;
          for (let i = 1; i < t.x.length; i++) total += Math.max(0, t.raw[rankKey][i] - t.raw[rankKey][i - 1]);
          return { t, total };
        }).sort((a, b) => b.total - a.total).slice(0, n);
        pids = [...new Set(ranked.map((r) => r.t.tgid))];
      } else {
        pids = sel;
      }
      // one line PER selected pid: sum that pid's tids per tick, then delta.
      const out = { x: [], y: [], lines: [] };
      for (const pid of pids) {
        const members = tidSeries.filter((t) => t.tgid === pid);
        const tick = new Map(); // x -> {sums}
        for (const t of members) {
          for (let i = 0; i < t.x.length; i++) {
            let e = tick.get(t.x[i]);
            if (!e) { e = {}; cols.forEach((c) => (e[c] = 0)); tick.set(t.x[i], e); }
            cols.forEach((c) => (e[c] += t.raw[c][i]));
          }
        }
        const xs = [...tick.keys()].sort((a, b) => a - b);
        const lx = [], ly = [];
        let prev = null, prevX = null;
        for (const x of xs) {
          const e = tick.get(x);
          if (prev) {
            const d = deltas(prev, e);
            if (d) {
              const v = metricExpr(d, { s: (x - prevX), ts: (x - prevX) * 1e9 });
              if (v != null) { lx.push(x); ly.push(v); }
            }
          }
          prev = e; prevX = x;
        }
        const comm = members[0] ? members[0].comm : null;
        out.lines.push({ pid, comm, x: lx, y: ly });
      }
      return out;
    }

    // mode 'tid'
    const selSet = new Set(sel);
    const out = { x: [], y: [], lines: [] };
    for (const t of tidSeries) {
      if (!selSet.has(t.tid)) continue;
      const lx = [], ly = [];
      let prev = null, prevX = null;
      for (let i = 0; i < t.x.length; i++) {
        if (prev) {
          const d = deltas(prev, at(t, i));
          if (d) {
            const v = metricExpr(d, { s: (t.x[i] - prevX), ts: (t.x[i] - prevX) * 1e9 });
            if (v != null) { lx.push(t.x[i]); ly.push(v); }
          }
        }
        prev = at(t, i); prevX = t.x[i];
      }
      out.lines.push({ tid: t.tid, comm: t.comm, tgid: t.tgid, x: lx, y: ly });
    }
    return out;
  };

  function at(t, i) { const o = {}; for (const k of Object.keys(t.raw)) o[k] = t.raw[k][i]; return o; }

  function pushSeries(store, mid, scale, label, pairs) {
    if (!pairs.length) return;
    let s = store.get(mid);
    if (!s) { s = { mid, x: [], y: [], scale, unit: V.SCALES[scale].unit, label }; store.set(mid, s); }
    for (const [x, y] of pairs) { s.x.push(x); s.y.push(y); }
  }

  V.scaleOf = scaleOf;
})(typeof window !== 'undefined' ? window : globalThis);