#!/usr/bin/env node
// eTrace-Diag viz — headless DOM verification of the full UI (jsdom).
// Substitutes for a real browser when none is available: loads index.html +
// all scripts into jsdom, drives the directory-picker flow against a real
// session DB, and asserts cards/panels/deep/logs rendering.
//
// Usage: node tools/viz/test/dom.mjs <session-dir> [--no-panels]
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const root = new URL('../../..', import.meta.url).pathname; // repo root
const vizDir = join(root, 'tools/viz');
// jsdom is a test-only dependency; resolve from ETRACE_DOM_NODE_MODULES if set.
const JSDOM = (() => {
  const nm = process.env.ETRACE_DOM_NODE_MODULES;
  const req = nm ? createRequire(join(nm, 'x.js')) : require;
  return req('jsdom').JSDOM;
})();

const dir = process.argv[2];
if (!dir || !existsSync(join(dir, 'etrace.sqlite3'))) {
  console.log('SKIP: need a session dir containing etrace.sqlite3');
  process.exit(0);
}

const SQL = await require(join(root, 'tools/viz/vendor/sql-wasm.js'))({
  locateFile: (f) => join(root, 'tools/viz/vendor', f),
});

const html = readFileSync(join(vizDir, 'index.html'), 'utf8');
const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'http://localhost:8901/index.html',
                              pretendToBeVisual: true });
const { window } = dom;
const { document } = window;

// ---- polyfills ----
window.File = File; // node global File
window.initSqlJs = async () => SQL;
window.eval('var initSqlJs = window.initSqlJs;'); // make it a global var binding
window.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 0);
window.confirm = () => true;
window.alert = () => {};
window.localStorage.clear();
window.fetch = async (path, opts) => {
  const clean = String(path).replace(/^\//, '');
  const p = join(root, clean);
  if (!existsSync(p)) return { ok: false, status: 404 };
  // directory listing: mimic python http.server HTML (consumed by listSessions)
  if (statSync(p).isDirectory()) {
    const entries = readdirSync(p).filter((n) => statSync(join(p, n)).isDirectory());
    const lis = entries.map((n) => `<li><a href="${n}/">${n}/</a></li>`).join('\n');
    return { ok: true, status: 200, text: async () => `<html><ul>\n${lis}\n</ul></html>` };
  }
  if (opts && opts.method === 'HEAD') return { ok: true, status: 200 };
  return { ok: true, status: 200, arrayBuffer: async () => readFileSync(p) };
};

// jsdom lacks canvas 2D; stub a minimal context that counts fillRect calls so
// tests can assert frames were actually painted.
window._fillRects = 0;
Object.defineProperty(window.HTMLCanvasElement.prototype, 'clientWidth',
  { configurable: true, get() { return Number(this.getAttribute('width')) || 800; } });
window.HTMLCanvasElement.prototype.getContext = function () {
  if (!this._ctx) {
    const win = window;
    this._ctx = new Proxy({}, {
      get(t, k) {
        if (k === 'canvas') return this;
        if (k === 'fillStyle' || k === 'strokeStyle' || k === 'font' ||
            k === 'lineWidth' || k === 'globalAlpha' || k === 'textAlign' ||
            k === 'textBaseline' || k === 'globalCompositeOperation') return '';
        if (k === 'fillRect' || k === 'strokeRect') {
          return () => { win._fillRects++; };
        }
        if (typeof k === 'string' && (k.startsWith('set') || k.startsWith('begin') ||
            k.startsWith('moveTo') || k.startsWith('lineTo') || k.startsWith('rect') ||
            k.startsWith('arc') || k.startsWith('fill') || k.startsWith('stroke') ||
            k.startsWith('clear') || k.startsWith('clip') || k.startsWith('close') ||
            k.startsWith('save') || k.startsWith('restore') || k.startsWith('translate') ||
            k.startsWith('scale') || k.startsWith('drawImage') || k.startsWith('fillText') ||
            k.startsWith('measureText'))) {
          return () => ({ width: 0 });
        }
        return t[k];
      },
      set() { return true; },
    });
  }
  return this._ctx;
};

// ---- run scripts in index.html order ----
for (const f of ['js/util.js', 'js/db.js', 'js/parse.js', 'js/chart.js', 'js/flame.js',
                 'js/panels.js', 'js/ui.js', 'js/main.js']) {
  window.eval(readFileSync(join(vizDir, f), 'utf8'));
}
const V = window.V;
const $ = (id) => document.getElementById(id);
let failures = 0;
const check = (ok, msg) => {
  if (ok) console.log('  ok: ' + msg);
  else { failures++; console.log('  FAIL: ' + msg); }
};

// ---- boot: 输出目录发现 → 会话列表 → 默认加载最新 ----
// 第一个 dom 走默认 out/（DEFAULT_OUT），验证打开即列出并加载（无目录选择器）。
const name = dir.split('/').filter(Boolean).pop();
// DOMContentLoaded 触发 bootFromOutputDir；轮询加载完成
await new Promise((resolve) => {
  const t0 = Date.now();
  const iv = setInterval(() => {
    const st = $('lblStatus').textContent;
    if (st.startsWith('已加载') || st.startsWith('无法列出') || Date.now() - t0 > 30000) {
      clearInterval(iv); resolve();
    }
  }, 50);
});
const bootStatus = $('lblStatus').textContent;
console.log('boot status: ' + bootStatus);
check(bootStatus.startsWith('已加载'), '默认 out/ 发现会话并加载');
check([...$('selSession').options].length >= 2, '会话下拉已列出（无目录选择器）');

const status = $('lblStatus').textContent;
console.log('status: ' + status);
check(status.startsWith('已加载'), '会话加载成功');

// ---- overview cards ----
const cards = document.querySelectorAll('#cards .card');
check(cards.length === 10, `总览 10 张卡片 (${cards.length})`);
const stageCard = [...cards].find((c) => c.querySelector('.card-title').textContent === '阶段');
check(!!stageCard && stageCard.textContent.includes('BASE / 已结束'), '阶段卡 = BASE / 已结束');

// ---- panels ----
const panels = document.querySelectorAll('#panelHost .panel');
check(panels.length === 8, `默认 8 面板 (${panels.length})`);
const cpuPanel = [...panels].find((p) => p.querySelector('.p-title').textContent === 'CPU 利用率');
check(!!cpuPanel && cpuPanel.querySelectorAll('.legend-chip').length === 2, 'CPU 面板 2 序列图例');

// ---- deep tab ----
const selEp = $('selEpisode');
check(selEp.options.length >= 1 && selEp.options[0].textContent.includes('#1'), 'DEEP episode 列表');
$('btnLoadDeep').click();
await new Promise((r) => setTimeout(r, 600)); // loadDeep async
const dt = $('dtSeries');
check(dt.querySelectorAll('.deep-tile').length >= 1, 'DEEP 逐线程趋势小方块渲染');
check(dt.querySelectorAll('.deep-tile').length >= 4, `DEEP 细粒度指标小方块多图 (${dt.querySelectorAll('.deep-tile').length} 个)`);
const flameHost = $('dtFlame');
check(flameHost.querySelector('canvas') !== null, '火焰图 canvas 存在');
// 切到火焰图子 tab → ResizeObserver 触发重绘（容器由 hidden 变可见）
document.querySelectorAll('#deepTabs button').forEach((b) => { if (b.dataset.dt === 'flame') b.click(); });
await new Promise((r) => setTimeout(r, 150));
const flameCanvas = flameHost.querySelector('canvas');
check(flameCanvas && flameCanvas.width > 0 && flameCanvas.height > 0, '火焰图切 tab 后实际渲染（canvas 有尺寸）');
const hotHost = $('dtHot');
const hotTables = hotHost.querySelectorAll('table.htable');
check(hotTables.length >= 3, `热点表 >=3 (${hotTables.length})`);
// 热点表列：pid/进程名/tid/线程名 + syscall 名 + lock 符号
const syscallCols = [...hotHost.querySelectorAll('table.htable th')].map((t) => t.textContent);
check(syscallCols.includes('pid'), '热点表含 pid 列');
check(syscallCols.includes('进程名'), '热点表含进程名列');
check(syscallCols.includes('tid'), '热点表含 tid 列');
check(syscallCols.includes('线程名'), '热点表含线程名列');
check(syscallCols.includes('系统调用名'), '热点表含系统调用名列');
check(syscallCols.includes('符号'), '锁竞争表含符号列');
// pid 筛选下拉存在
check($('hotPid') !== null, '热点表进程筛选下拉存在');
check($('hotPid').options.length >= 2, `进程筛选含多个进程 (${$('hotPid').options.length})`);

// ---- logs tab ----
$('tabs').querySelector('button[data-tab="logs"]').click();
await new Promise((r) => setTimeout(r, 100));
const logRows = document.querySelectorAll('#logView .log-line');
check(logRows.length >= 3, `日志行 >=3 (${logRows.length})`);
const warn = [...logRows].find((r) => r.textContent.includes('WARN'));
check(!!warn, 'WARN 日志行存在');
check(warn && warn.querySelector('button') !== null, '「定位到图表时段」按钮');

// ---- 火焰图真实绘制（fillRect 计数）----
$('tabs').querySelector('button[data-tab="deep"]').click();
document.querySelectorAll('#deepTabs button').forEach((b) => { if (b.dataset.dt === 'flame') b.click(); });
await new Promise((r) => setTimeout(r, 200));
const frBefore = window._fillRects;
check(frBefore > 0, `火焰图已绘制帧矩形 (fillRect=${frBefore})`);

// ---- 趋势小方块点击 → 放大弹窗 ----
document.querySelectorAll('#deepTabs button').forEach((b) => { if (b.dataset.dt === 'series') b.click(); });
await new Promise((r) => setTimeout(r, 200));
const tile = $('dtSeries').querySelector('.deep-tile');
check(tile !== null, '趋势小方块存在');
tile.click();
await new Promise((r) => setTimeout(r, 100));
const dlg = document.getElementById('dlgTrend');
check(dlg !== null && dlg.querySelector('canvas') !== null && dlg.textContent.includes('在核占比'),
  '点击小方块打开放大弹窗（含图表）');
// 用带 ?out= 的 URL 重建一个 JSDOM：boot 应列出输出目录下的会话（fetch 目录列表
// + HEAD 探测 etrace.sqlite3），默认选中最新并加载——验证「启动到输出文件夹→选会话」。
const autoUrl = 'http://localhost:8901/index.html?out=out';
const autoDom = new JSDOM(html, { runScripts: 'outside-only', url: autoUrl,
                                  pretendToBeVisual: true });
const aw = autoDom.window;
aw.File = File;
aw.initSqlJs = async () => SQL;
aw.eval('var initSqlJs = window.initSqlJs;');
aw.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 0);
aw.confirm = () => true;
aw.alert = () => {};
aw.localStorage.clear();
aw.fetch = window.fetch; // reuse stub
aw.HTMLCanvasElement.prototype.getContext = window.HTMLCanvasElement.prototype.getContext;
for (const f of ['js/util.js', 'js/db.js', 'js/parse.js', 'js/chart.js', 'js/flame.js',
                 'js/panels.js', 'js/ui.js', 'js/main.js']) {
  aw.eval(readFileSync(join(vizDir, f), 'utf8'));
}
const a$ = (id) => aw.document.getElementById(id);
// DOMContentLoaded fires on next tick in jsdom; poll for auto-load result
await new Promise((resolve) => {
  const t0 = Date.now();
  const iv = setInterval(() => {
    const st = a$('lblStatus').textContent;
    if (st.startsWith('已加载') || st.startsWith('无法列出') || Date.now() - t0 > 30000) {
      clearInterval(iv); resolve();
    }
  }, 50);
});
const outStatus = a$('lblStatus').textContent;
console.log('out-dir status: ' + outStatus);
check(outStatus.startsWith('已加载'), '?out= 输出目录发现会话并加载（免目录选择器）');
const opts = [...a$('selSession').options].map((o) => o.value);
check(opts.length >= 2, `会话下拉已列出输出目录会话 (${opts.length} 个)`);
// 断言针对真实 out/ 下的最新会话（dom 参数目录可能不在 out/ 中）
const latestOut = readdirSync(join(root, 'out')).filter((n) =>
  /^\d{8}-\d{6}_\d+$/.test(n) && existsSync(join(root, 'out', n, 'etrace.sqlite3'))).sort().reverse()[0];
check(opts.includes(latestOut), `下拉包含 out/ 最新会话 ${latestOut}`);
check(a$('selSession').value === latestOut, '默认选中 out/ 最新会话');
check(aw.document.querySelectorAll('#cards .card').length === 10, '会话加载后卡片渲染');
check(a$('btnReload').disabled === false, '「重新加载」可用');

// ---- 场景：服务器根不含 out/（如 --directory tools/viz）→ /out/ 404 → 明确指引 ----
const errDom = new JSDOM(html, { runScripts: 'outside-only', url: 'http://localhost:8901/index.html',
                                  pretendToBeVisual: true });
const ew = errDom.window;
ew.File = File;
ew.initSqlJs = async () => SQL;
ew.eval('var initSqlJs = window.initSqlJs;');
ew.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 0);
ew.confirm = () => true;
ew.alert = () => {};
ew.localStorage.clear();
ew.fetch = async () => ({ ok: false, status: 404 }); // /out/ 不可达
ew.HTMLCanvasElement.prototype.getContext = window.HTMLCanvasElement.prototype.getContext;
for (const f of ['js/util.js', 'js/db.js', 'js/parse.js', 'js/chart.js', 'js/flame.js',
                 'js/panels.js', 'js/ui.js', 'js/main.js']) {
  ew.eval(readFileSync(join(vizDir, f), 'utf8'));
}
await new Promise((resolve) => {
  const t0 = Date.now();
  const iv = setInterval(() => {
    const st = ew.document.getElementById('lblStatus').textContent;
    if (st.startsWith('无法列出') || st.startsWith('已加载') || Date.now() - t0 > 30000) {
      clearInterval(iv); resolve();
    }
  }, 50);
});
const errStatus = ew.document.getElementById('lblStatus').textContent;
console.log('404 status: ' + errStatus);
check(errStatus.startsWith('无法列出') && errStatus.includes('serve.py'),
  'out/ 不可达时给出内置服务指引（不再卡在「扫描」）');

if (failures) { console.log(`\nDOM FAIL (${failures})`); process.exit(1); }
console.log('\nDOM OK');
process.exit(0);
