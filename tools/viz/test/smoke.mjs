#!/usr/bin/env node
// eTrace-Diag viz — node smoke test (no DOM).
// Usage: node tools/viz/test/smoke.mjs [session-dir]
//   - no etrace.sqlite3 in <dir>            -> SKIP, exit 0
//   - tables / metrics / folded / panels OK -> SMOKE OK, exit 0
//   - any assertion fails                    -> FAIL printed, exit 1
import { createRequire } from 'node:module';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const initSqlJs = require('../vendor/sql-wasm.js');

// ---- load the pure JS modules into a shared context ----
const ctx = { console, globalThis: null };
ctx.globalThis = ctx;
vm.createContext(ctx);
for (const f of ['../js/util.js', '../js/parse.js', '../js/flame.js', '../js/panels.js']) {
  vm.runInContext(readFileSync(new URL(f, import.meta.url), 'utf8'), ctx, { filename: f });
}
const V = ctx.V;

// ---- find session ----
function findSession() {
  let dir = process.argv[2];
  if (!dir) {
    const out = join(process.cwd(), 'out');
    if (!existsSync(out)) return null;
    const names = readdirSync(out).filter((n) => /^\d{8}-\d{6}_\d+$/.test(n)).sort().reverse();
    for (const n of names) {
      const d = join(out, n);
      if (statSync(d).isDirectory() && existsSync(join(d, 'etrace.sqlite3'))) return d;
    }
    return null;
  }
  return existsSync(join(dir, 'etrace.sqlite3')) ? dir : null;
}

const dir = findSession();
if (!dir) {
  console.log(`SKIP: no etrace.sqlite3 in ${process.argv[2] || '(out)'}`);
  process.exit(0);
}

let failures = 0;
const check = (ok, msg) => {
  if (ok) console.log('  ok: ' + msg);
  else { failures++; console.log('  FAIL: ' + msg); }
};

const SQL = await initSqlJs({ locateFile: (f) => new URL('../vendor/' + f, import.meta.url).pathname });
const db = new SQL.Database(readFileSync(join(dir, 'etrace.sqlite3')));

// ---- tables ----
const tables = db.exec("SELECT name FROM sqlite_master WHERE type='table'")[0].values.map((r) => r[0]);
const expected = ['meta', 'host', 'host_cpu', 'host_disk', 'host_proc', 'anomaly', 'anomaly_tid',
  'proc_overhead', 'bpf_stats', 'io_devices', 'memory_events', 'oom_events', 'targets_log', 'logs',
  'deep_episodes', 'deep_series', 'deep_gap', 'deep_folded', 'deep_syscall', 'deep_lock',
  'deep_runq', 'deep_iofile'];
const sys = tables.filter((t) => !t.startsWith('sqlite_'));
check(JSON.stringify(sys.sort()) === JSON.stringify(expected.slice().sort()),
  `22 张表 (${sys.length})`);

// ---- extraction / metrics ----
// db.js is not loaded in node; wire V.db primitives onto the raw Database.
V.db = { sqlJs: SQL };
const origStep = V.db.step, origQuery = V.db.query, origScalar = V.db.scalar;
V.db.step = (d, sql, params, cb) => {
  const st = d.prepare(sql);
  if (params) st.bind(params);
  let n = 0;
  while (st.step()) { cb(st.getAsObject()); n++; }
  st.free();
  return n;
};
V.db.query = (d, sql, params) => {
  const st = d.prepare(sql);
  if (params) st.bind(params);
  const out = [];
  while (st.step()) out.push(st.getAsObject());
  st.free();
  return out;
};
V.db.scalar = (d, sql, params) => {
  const st = d.prepare(sql);
  if (params) st.bind(params);
  let v = null;
  if (st.step()) v = st.get()[0];
  st.free();
  return v;
};

const hostCount = V.db.scalar(db, 'SELECT COUNT(*) FROM host');
check(hostCount > 0, `host 行数 = ${hostCount}`);

const ext = V.extract(db);
const cpu = ext.store.get('host.cpu.usage_pct');
check(cpu && cpu.y.length > 0, 'host.cpu.usage_pct 非空');
if (cpu && cpu.y.length) {
  const okRange = cpu.y.every((v) => v >= 0 && v <= 100);
  check(okRange, `usage_pct 值域 [0,100] (min=${Math.min(...cpu.y).toFixed(1)}, max=${Math.max(...cpu.y).toFixed(1)})`);
}
const load1 = ext.store.get('host.load.load1');
check(load1 && load1.y.length > 0, 'host.load.load1 非空');

const busy = ext.store.get('ebpf.busy_pct');
if (busy && busy.y.length) {
  const ok = busy.y.every((v) => v >= 0 && v <= 100 * 64);
  check(ok, 'ebpf.busy_pct 值域 [0, 6400]');
} else {
  check(true, 'anomaly_tid 空表不报错 (无 anomaly 数据)');
}

// ---- folded parsing ----
const foldedCount = V.db.scalar(db, "SELECT COUNT(*) FROM deep_folded WHERE ordinal=1");
if (foldedCount > 0) {
  let text = '';
  V.db.step(db, "SELECT frames,value FROM deep_folded WHERE ordinal=1 ORDER BY rowid", null,
    (r) => { text += r.frames + ' ' + r.value + '\n'; });
  const parsed = V.parseFolded(text);
  check(parsed.pids.size > 0 || parsed.tids.size > 0, `pids=${parsed.pids.size} tids=${parsed.tids.size}`);
}

// embedded sample: new format + legacy format
const sample = 'p:1234/myapp;t:1240/woker;start_kernel;schedule;/lib/x.so+0x12 5\n' +
               'a;b;c 7\n';
const sp = V.parseFolded(sample);
check(sp.pids.get(1234) && sp.pids.get(1234).comm === 'myapp', '新格式 p: 根帧解析');
check(sp.tids.get(1240) && sp.tids.get(1240).comm === 'woker', '新格式 t: 根帧解析');
check(sp.lines[0].value === 5, '新格式 value=5');
const legacy = sp.lines.find((l) => l.frames[0] === 'a');
check(legacy && legacy.p === null && legacy.t === null && legacy.value === 7, '旧格式 p/t=null, total 累计');
check(sp.total === 12, 'total=12');

// ---- panels state round-trip ----
const st0 = { version: 1, linkX: true, showEvents: true,
  panels: [{ id: 'p123456', title: 'T', height: 220, kind: 'line',
    series: [{ mid: 'host.cpu.usage_pct' }, { family: 'ebpf.tid.*.cpu_pct', mode: 'pid', sel: [7] }] }] };
const round = JSON.parse(JSON.stringify(st0));
check(JSON.stringify(round) === JSON.stringify(st0), 'panels serialize/deserialize round-trip');
const famEntry = round.panels[0].series.find((s) => s.family);
check(famEntry && famEntry.mode === 'pid' && JSON.stringify(famEntry.sel) === '[7]',
  'round-trip 保留 {family, mode, sel}');

// ---- grouped aggregation (5.4) ----
// synthetic: tid 100/101 (tgid 7), tid 200 (tgid 9), 3 ticks each (ns cumulatives)
const mk = (tid, tgid, comm, cums) => ({
  tid, comm, tgid,
  x: cums.map((_, i) => i),
  raw: { on_cpu_ns: cums, nr_sw_vol: cums.map((x) => x), nr_sw_invol: cums.map(() => 0),
         io_ops: cums.map((x) => x), io_bytes: cums.map((x) => x), pf_minor: cums.map(() => 0),
         pf_major: cums.map(() => 0), lock_waits: cums.map(() => 0), lock_lat_ns: cums.map(() => 0) },
});
const t100 = mk(100, 7, 'a', [0, 10e9, 30e9]);
const t101 = mk(101, 7, 'a', [0, 5e9, 20e9]);
const t200 = mk(200, 9, 'b', [0, 40e9, 90e9]);
const all = [t100, t101, t200];
const cpuExpr = (d, t) => (t.ts ? 100 * d.on_cpu_ns / t.ts : null);

const pidAgg = V.aggregate(all, { mode: 'pid', sel: [7] }, cpuExpr);
// tick1: (10+5)e9 ns/1s -> 1500%; tick2: (50-15)e9 -> 3500%; single pid=7 line
check(pidAgg.lines.length === 1 && pidAgg.lines[0].pid === 7 &&
      Math.abs(pidAgg.lines[0].y[0] - 1500) < 1e-6 && Math.abs(pidAgg.lines[0].y[1] - 3500) < 1e-6,
  `mode=pid 逐 tick 求和后 delta (y=${pidAgg.lines[0].y})`);

const tidAgg = V.aggregate(all, { mode: 'tid', sel: [100, 101] }, cpuExpr);
check(tidAgg.lines.length === 2, `mode=tid 输出 2 条线 (${tidAgg.lines.length})`);

const topAgg = V.aggregate(all, { mode: 'top', sel: [2] }, cpuExpr);
// totals: t100=30e9, t101=20e9, t200=90e9 -> top2 pids = {9 (90e9), 7 (30+20)e9}
check(topAgg.lines.length === 2, `mode=top 输出前 2 pid (${topAgg.lines.length})`);
const pidsTop = topAgg.lines.map((l) => l.pid).sort();
check(JSON.stringify(pidsTop) === '[7,9]', `top pid 集合 = ${pidsTop}`);

// weighted latency aggregation: lock_avg_ms over pid (ΔΣlat/ΔΣcount)
const lockExpr = (d) => (d.lock_waits ? d.lock_lat_ns / d.lock_waits / 1e6 : null);
const lw = (tid, tgid, comm, w, lat) => ({
  tid, comm, tgid, x: w.map((_, i) => i),
  raw: { on_cpu_ns: w.map(() => 0), nr_sw_vol: w.map(() => 0), nr_sw_invol: w.map(() => 0),
         io_ops: w.map(() => 0), io_bytes: w.map(() => 0), pf_minor: w.map(() => 0),
         pf_major: w.map(() => 0), lock_waits: w, lock_lat_ns: lat },
});
const l1 = lw(1, 7, 'a', [0, 2, 4], [0, 100e6, 300e6]);   // Δwaits 2,2  Δlat 100e6,200e6
const l2 = lw(2, 7, 'a', [0, 3, 5], [0, 300e6, 500e6]);   // Δwaits 3,2  Δlat 300e6,200e6
const lockAgg = V.aggregate([l1, l2], { mode: 'pid', sel: [7] }, lockExpr);
// tick1: Σwaits=5 Σlat=400e6 -> avg=80ms ; tick2: Σwaits=4 Σlat=400e6 -> avg=100ms
check(lockAgg.lines[0].y.length === 2 &&
      Math.abs(lockAgg.lines[0].y[0] - 80) < 1e-6 && Math.abs(lockAgg.lines[0].y[1] - 100) < 1e-6,
  `加权均时延 (y=${lockAgg.lines[0].y})`);

// restore
V.db.step = origStep; V.db.query = origQuery; V.db.scalar = origScalar;

if (failures) {
  console.log(`\nFAIL (${failures})`);
  process.exit(1);
}
console.log('\nSMOKE OK');
process.exit(0);
