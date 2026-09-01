/* eTrace-Diag viz — per-tab rendering: overview cards, panel host, DEEP, logs.
 * Depends on chart/flame/panels/parse.
 */
(function (global) {
  'use strict';
  const V = global.V = global.V || {};

  // ------------------------------------------------------------------
  // Overview cards
  // ------------------------------------------------------------------
  V.renderCards = function (session) {
    const host = document.getElementById('cards');
    host.textContent = '';
    const st = session.store;
    const lastVal = (mid) => {
      const s = st.get(mid);
      if (!s || !s.y.length) return null;
      for (let i = s.y.length - 1; i >= 0; i--) if (s.y[i] != null) return s.y[i];
      return null;
    };
    const mean60 = (mid) => {
      const s = st.get(mid);
      if (!s || !s.y.length) return null;
      const x0 = Math.max(s.x[s.x.length - 1] - 60, s.x[0]);
      let acc = 0, n = 0;
      for (let i = s.x.length - 1; i >= 0 && s.x[i] >= x0; i--) { if (s.y[i] != null) { acc += s.y[i]; n++; } }
      return n ? acc / n : null;
    };
    const card = (title, val, sub) => {
      const el = V.el('div', { class: 'card' },
        [V.el('div', { class: 'card-title' }, title),
         V.el('div', { class: 'card-val' }, val == null ? '—' : String(val)),
         V.el('div', { class: 'card-sub' }, sub || '')]);
      host.appendChild(el);
    };

    const u = (v) => (v == null ? '—' : V.fmt.num(v, 1));
    card('CPU 利用率', u(lastVal('host.cpu.usage_pct')) + '%', '60s 均值 ' + u(mean60('host.cpu.usage_pct')) + '%');
    card('内存', u(lastVal('host.mem.used_pct')) + '%', '60s 均值 ' + u(mean60('host.mem.used_pct')) + '%');
    card('Swap', u(lastVal('host.mem.swap_used_pct')) + '%', '60s 均值 ' + u(mean60('host.mem.swap_used_pct')) + '%');
    card('Load1', u(lastVal('host.load.load1')), '60s 均值 ' + u(mean60('host.load.load1')));
    card('运行队列', u(lastVal('host.load.nr_running')), '60s 均值 ' + u(mean60('host.load.nr_running')));
    card('PSI-cpu', u(lastVal('host.psi.cpu.some.avg10')), '60s 均值 ' + u(mean60('host.psi.cpu.some.avg10')));
    card('PSI-io', u(lastVal('host.psi.io.some.avg10')), '60s 均值 ' + u(mean60('host.psi.io.some.avg10')));
    card('PSI-mem', u(lastVal('host.psi.mem.some.avg10')), '60s 均值 ' + u(mean60('host.psi.mem.some.avg10')));
    card('TCP重传', u(lastVal('net.tcp.retrans_s')), '60s 均值 ' + u(mean60('net.tcp.retrans_s')));
    card('采集器CPU', u(lastVal('ovh.cpu_pct')) + '%', '60s 均值 ' + u(mean60('ovh.cpu_pct')) + '%');

    // 阶段卡
    const running = session.runningDeep; // ordinal or null
    const stageEl = V.el('div', { class: 'card' },
      [V.el('div', { class: 'card-title' }, '阶段'),
       V.el('div', { class: 'card-val' + (running ? ' stage-deep' : ''),
             }, running ? ('DEEP #' + running + ' 进行中') : 'BASE / 已结束'),
       V.el('div', { class: 'card-sub' }, running ? '取证采集中' : '')]);
    host.appendChild(stageEl);
  };

  // ------------------------------------------------------------------
  // Panel host (overview)
  // ------------------------------------------------------------------
  let panelLink = null;
  V.ensurePanelLink = function () { if (!panelLink) panelLink = new V.LinkGroup(); return panelLink; };
  // DEEP 趋势专用联动组：与总览面板隔离开，互不拖动对方视口
  let deepLink = null;
  V.ensureDeepLink = function () { if (!deepLink) deepLink = new V.LinkGroup(); return deepLink; };
  V.renderPanelHost = function (session) {
    const host = document.getElementById('panelHost');
    // 重建前销毁旧图表（从 LinkGroup 摘除、断开 ResizeObserver），避免泄漏
    for (const el of host.querySelectorAll('.panel')) if (el._chart) el._chart.destroy();
    host.textContent = '';
    const link = V.ensurePanelLink();

    for (const p of V.panels.state.panels) {
      const el = V.renderPanel(session, p, link);
      host.appendChild(el);
    }
    return host;
  };

  // 展开一个面板定义的全部 series → [{id,label,x,y,unit,scaleName,kind,scale}]，
  // 小方块与「点击放大」共用同一份解析逻辑；2 个量纲时第 2 个上右轴。
  function collectPanelLines(session, def) {
    const kind = def.kind === 'area' ? 'area' : def.kind === 'step' ? 'step' : 'line';
    const adds = [];
    for (const entry of def.series) {
      if (entry.mid) {
        const s = session.store.get(entry.mid);
        if (s) {
          adds.push({ id: entry.mid, label: s.label, x: s.x, y: s.y,
                      unit: s.unit, scaleName: V.scaleOf(entry.mid), kind });
        } else {
          // 本会话无此指标数据 → 占位空序列（图例里保留条目）
          adds.push({ id: entry.mid + ':empty', label: entry.mid + '（无数据）', x: [], y: [], kind });
        }
      } else if (entry.family) {
        const fam = V.expandFamilyFor(entry, session);
        for (const l of fam) {
          adds.push({ id: l.id, label: l.label, x: l.x, y: l.y,
                      unit: l.unit, scaleName: l.scaleName, kind });
        }
        if (!fam.length) {
          adds.push({ id: entry.family + ':empty', label: entry.family + '（无数据）', x: [], y: [], kind });
        }
      }
    }
    const scaleOrder = [...new Set(adds.map((a) => a.scaleName).filter(Boolean))];
    const sideOf = (sn) => (sn && scaleOrder[1] === sn ? 'right' : 'left');
    return adds.map((a) => ({ ...a, scale: sideOf(a.scaleName) }));
  }

  // render one panel definition -> DOM
  V.renderPanel = function (session, def, link) {
    const panel = V.el('div', { class: 'panel', 'data-id': def.id });
    const head = V.el('div', { class: 'panel-head' },
      [V.el('span', { class: 'drag', draggable: 'true', title: '拖拽排序' }, '⠿'),
       V.el('span', { class: 'p-title' }, def.title),
       V.el('button', { class: 'p-edit', title: '编辑' }, '✎'),
       V.el('button', { class: 'p-del', title: '删除' }, '✕')]);
    panel.appendChild(head);

    // 小方块：固定高度、无图例（与 DEEP 逐线程小方块一致的形态）
    const canvas = document.createElement('canvas');
    const chart = new V.TChart(canvas, {
      link, height: 140, legend: false,
      events: session.events, bands: session.bands, wall: session.wall,
    });
    panel._chart = chart;
    for (const a of collectPanelLines(session, def)) chart.addSeries(a);
    panel.appendChild(chart.wrap);

    // 点击小方块 → 全尺寸弹窗（拖拽/头部控件点击不触发）
    panel.addEventListener('click', (e) => {
      if (e.target.closest('.panel-head')) return;
      if (chart.movedPx <= 5) V.openPanelViewDialog(session, def);
    });

    // ---- drag & drop ordering ----
    const drag = head.querySelector('.drag');
    drag.addEventListener('dragstart', (e) => { e.dataTransfer.setData('text/plain', def.id); });
    panel.addEventListener('dragover', (e) => {
      e.preventDefault();
      const r = panel.getBoundingClientRect();
      const top = (e.clientY - r.top) < r.height / 2;
      panel.classList.toggle('dragover-top', top);
      panel.classList.toggle('dragover-bottom', !top);
    });
    panel.addEventListener('dragleave', () => {
      panel.classList.remove('dragover-top', 'dragover-bottom');
    });
    panel.addEventListener('drop', (e) => {
      e.preventDefault();
      panel.classList.remove('dragover-top', 'dragover-bottom');
      const srcId = e.dataTransfer.getData('text/plain');
      if (srcId === def.id) return;
      const list = V.panels.state.panels;
      const src = list.find((p) => p.id === srcId);
      const dst = list.find((p) => p.id === def.id);
      if (!src || !dst) return;
      const r = panel.getBoundingClientRect();
      const before = (e.clientY - r.top) < r.height / 2;
      list.splice(list.indexOf(src), 1);
      const di = list.indexOf(dst);
      list.splice(before ? di : di + 1, 0, src);
      V.panels.saveSoon();
      V.renderPanelHost(session);
    });

    // edit / delete
    head.querySelector('.p-edit').addEventListener('click', () => V.openPanelDialog(session, def));
    head.querySelector('.p-del').addEventListener('click', () => {
      if (!confirm('删除面板「' + def.title + '」？')) return;
      V.panels.state.panels = V.panels.state.panels.filter((p) => p.id !== def.id);
      V.panels.saveSoon();
      V.renderPanelHost(session);
    });
    return panel;
  };

  // expand a family entry using the grouped model
  V.expandFamilyFor = function (entry, session) {
    const fam = entry.family;
    if (fam.startsWith('host.proc.')) {
      const metric = fam.endsWith('cpu_pct') ? 'cpu_pct' : 'rss_mb';
      const keySuffix = metric === 'cpu_pct' ? 'cpu_pct' : 'rss_mb';
      // collect all per-pid series for that metric
      const mids = [...session.store.keys()].filter((m) => m.startsWith('host.proc.') && m.endsWith('.' + keySuffix));
      const sorted = mids.sort((a, b) => {
        const sa = session.store.get(a), sb = session.store.get(b);
        const la = sa.y.length ? sa.y[sa.y.length - 1] : 0;
        const lb = sb.y.length ? sb.y[sb.y.length - 1] : 0;
        return lb - la;
      });
      let selected = sorted;
      if (entry.mode === 'top') selected = sorted.slice(0, entry.sel && entry.sel.length ? entry.sel[0] : 5);
      else if (entry.sel && entry.sel.length) {
        const selSet = new Set(entry.sel.map(Number));
        selected = sorted.filter((m) => selSet.has(Number(m.split('.')[2])));
      }
      return selected.map((m) => {
        const s = session.store.get(m);
        return { id: m, label: s.label, x: s.x, y: s.y, scale: 'left', unit: s.unit, scaleName: s.scale };
      });
    }
    if (fam.startsWith('net.iface.') || fam.startsWith('gpu.')) {
      // prefix = fam with the "*" replaced by "" → e.g. "net.iface..rx_mbps"
      const prefix = fam.replace('*', '');
      const mids = [...session.store.keys()].filter((m) => m.startsWith(prefix));
      let selected = mids;
      if (entry.mode === 'sel' && entry.sel && entry.sel.length) {
        const selSet = new Set(entry.sel);
        selected = mids.filter((m) => selSet.has(m.split('.')[2]));
      }
      return selected.map((m) => {
        const s = session.store.get(m);
        return { id: m, label: s.label, x: s.x, y: s.y, scale: 'left', unit: s.unit, scaleName: s.scale };
      });
    }
    if (fam.startsWith('ebpf.tid.')) {
      const metric = fam.split('.*.')[1] || 'cpu_pct';
      const expr = V.deepExpr(metric);
      if (!expr) return [];   // 未知指标 id（如旧面板配置残留）→ 不静默画错数据
      const dm = V.DEEP_METRICS.find((x) => x.id === metric);
      const mUnit = dm ? dm.unit : null;
      const mScale = fam.includes('cpu_pct') ? 'pct'
        : fam.includes('io_mbs') ? 'mbps'
        : fam.includes('avg_ms') ? 'ms' : 'rate';
      const entries = [...session.tidRaw.values()];
      if (entry.mode === 'tid') {
        const selSet = new Set(entry.sel);
        const out = [];
        for (const t of entries) {
          if (!selSet.has(t.tid)) continue;
          const agg = V.aggregate([t], { mode: 'tid', sel: [t.tid] }, expr);
          const l = agg.lines[0];
          if (l) out.push({ id: 'tid:' + t.tid, label: (t.comm || 'tid') + ' (' + t.tid + ')', x: l.x, y: l.y,
                           scale: 'left', unit: mUnit, scaleName: mScale });
        }
        return out;
      }
      const agg = V.aggregate(entries, { mode: entry.mode, sel: entry.sel }, expr);
      return agg.lines.map((l) => ({
        id: 'pid:' + l.pid, label: 'pid ' + l.pid, x: l.x, y: l.y, scale: 'left', unit: mUnit, scaleName: mScale,
      }));
    }
    return [];
  };

  // deep metric expression (shared with DEEP trend tab)
  // 未知指标返回 null（调用方拒绝），绝不静默回退到别的指标 —— 曾导致「线程缺页」画成在核占比
  V.deepExpr = function (id) {
    const m = V.DEEP_METRICS.find((x) => x.id === id);
    return m ? (d, t) => m.expr(d, t) : null;
  };

  // ------------------------------------------------------------------
  // DEEP tab
  // ------------------------------------------------------------------
  V.renderDeepTab = function (session) {
    const sel = document.getElementById('selEpisode');
    sel.textContent = '';
    const eps = session.episodes;
    if (!eps.length) {
      const o = V.el('option', { value: '' }, '该会话无 DEEP 取证');
      sel.appendChild(o);
      document.getElementById('btnLoadDeep').disabled = true;
      return;
    }
    for (const ep of eps) {
      const running = ep.running;
      const o = V.el('option', { value: ep.ordinal },
        '#' + ep.ordinal + ' · ' + (ep.startWall || '?') + ' · 时长 ' + (ep.dur || '?') + 's' +
        (running ? '（未收尾）' : ''));
      sel.appendChild(o);
    }
    document.getElementById('btnLoadDeep').disabled = false;
  };

  V.deepCache = {};

  V.loadDeep = async function (session, ordinal) {
    const db = session.db;
    const p = document.getElementById('deepProgress');
    p.textContent = '加载中…';
    if (V.deepCache[ordinal]) {
      V.renderDeepEvidence(session, V.deepCache[ordinal]);
      p.textContent = '';
      return;
    }
    const total = V.db.scalar(db, 'SELECT COUNT(*) FROM deep_series WHERE ordinal=?', [ordinal]);
    const series = new Map(); // tid -> {tid,comm,tgid,x,raw}
    let n = 0;
    V.db.step(db,
      `SELECT phase,ts_ns,tid,tgid,comm,on_cpu_ns,nr_sw_vol,nr_sw_invol,io_ops,io_bytes,` +
      `pf_minor,pf_major,lock_waits,lock_lat_ns,syscall_count,syscall_lat_ns,` +
      `futex_waits,futex_lat_ns,runq_wait_count,runq_wait_ns FROM deep_series ` +
      `WHERE ordinal=? ORDER BY phase,ts_ns,tid`, [ordinal], (r) => {
        let ts = series.get(r.tid);
        if (!ts) {
          ts = { tid: r.tid, comm: r.comm, tgid: r.tgid, x: [], phase: [],
                 raw: { on_cpu_ns: [], nr_sw_vol: [], nr_sw_invol: [], io_ops: [], io_bytes: [],
                        pf_minor: [], pf_major: [], lock_waits: [], lock_lat_ns: [],
                        syscall_count: [], syscall_lat_ns: [], futex_waits: [], futex_lat_ns: [],
                        runq_wait_count: [], runq_wait_ns: [] } };
          series.set(r.tid, ts);
        }
        ts.x.push((r.ts_ns - session.t0) / 1e9);
        ts.phase.push(r.phase);
        for (const k of Object.keys(ts.raw)) ts.raw[k].push(r[k] || 0);
        n++;
        if (total && (n % 2000 === 0)) p.textContent = `加载 ${n}/${total}`;
      });
    // folded
    const kinds = { on_cpu: '', off_cpu: '' };
    V.db.step(db, `SELECT kind,frames,value FROM deep_folded WHERE ordinal=? ORDER BY rowid`,
      [ordinal], (r) => { kinds[r.kind] += r.frames + ' ' + r.value + '\n'; });
    // hot tables
    const hot = {
      syscall: V.db.query(db, 'SELECT * FROM deep_syscall WHERE ordinal=? ORDER BY count DESC', [ordinal]),
      runq: V.db.query(db, 'SELECT * FROM deep_runq WHERE ordinal=? ORDER BY count DESC', [ordinal]),
      lock: V.db.query(db, 'SELECT * FROM deep_lock WHERE ordinal=? ORDER BY count DESC', [ordinal]),
      iofile: V.db.query(db, 'SELECT * FROM deep_iofile WHERE ordinal=? ORDER BY bytes DESC', [ordinal]),
      proc: V.db.query(db, 'SELECT * FROM deep_proc WHERE ordinal=? ORDER BY ts_ns', [ordinal]),
      iodev: V.db.query(db, 'SELECT * FROM deep_io_device WHERE ordinal=? ORDER BY ops DESC', [ordinal]),
      netflow: V.db.query(db, 'SELECT * FROM deep_net_flow WHERE ordinal=? ORDER BY tx_bytes DESC', [ordinal]),
      netdrop: V.db.query(db, 'SELECT * FROM deep_net_drop WHERE ordinal=? ORDER BY count DESC', [ordinal]),
      netsoft: V.db.query(db, 'SELECT * FROM deep_net_softirq WHERE ordinal=? ORDER BY count DESC', [ordinal]),
      gpuproc: V.db.query(db, 'SELECT * FROM deep_gpu_process WHERE ordinal=? ORDER BY ts_ns', [ordinal]),
      offcpu: V.db.query(db, 'SELECT * FROM deep_offcpu WHERE ordinal=? ORDER BY dwell_ns DESC', [ordinal]),
    };
    const gaps = V.db.query(db, 'SELECT ts_ns,from_head,to_head FROM deep_gap WHERE ordinal=? ORDER BY ts_ns', [ordinal]);
    const meta = V.db.scalar(db, 'SELECT meta_json FROM deep_episodes WHERE ordinal=?', [ordinal]);
    const summary = V.db.scalar(db, 'SELECT summary_text FROM deep_episodes WHERE ordinal=?', [ordinal]);
    const parsed = { on_cpu: V.parseFolded(kinds.on_cpu), off_cpu: V.parseFolded(kinds.off_cpu) };

    const cache = { series, hot, gaps, meta, summary, parsed };
    V.deepCache[ordinal] = cache;
    p.textContent = '';
    V.renderDeepEvidence(session, cache);
  };

  V.renderDeepEvidence = function (session, cache) {
    // summary
    const sumHost = document.getElementById('deepSummary');
    sumHost.textContent = '';
    if (cache.meta) {
      try {
        const m = JSON.parse(cache.meta);
        const tbl = V.el('table', {}, [V.el('tbody', {}, Object.entries(m).map(([k, v]) =>
          V.el('tr', {}, [V.el('th', {}, k), V.el('td', {}, typeof v === 'string' ? v : JSON.stringify(v))])))]);
        sumHost.appendChild(tbl);
      } catch (e) { /* ignore */ }
    }
    if (cache.summary) {
      sumHost.appendChild(V.el('pre', {}, cache.summary));
    }

    // series trends —— 小方块网格，点击放大查看
    const host = document.getElementById('dtSeries');
    // 重建前销毁旧 tile 图表（从联动组摘除、断开 ResizeObserver）
    for (const el of host.querySelectorAll('.deep-tile')) if (el._chart) el._chart.destroy();
    host.textContent = '';
    const trends = V.buildDeepTrends(session, cache.series, cache.gaps);
    const link = V.ensureDeepLink();
    for (const t of trends) {
      const canvas = document.createElement('canvas');
      const chart = new V.TChart(canvas, { link, height: 140, legend: false,
                                           events: session.events,
                                           bands: session.bands, wall: session.wall });
      for (const line of t.lines) {
        chart.addSeries({ id: line.id, label: line.label, x: line.x, y: line.y, scale: 'left',
                          unit: line.unit, scaleName: line.scaleName });
      }
      const tile = V.el('div', { class: 'deep-tile' },
        [V.el('div', { class: 'deep-tile-title' }, t.label), chart.wrap]);
      // 拖拽平移后松手会合成 click —— 位移超阈值视为拖拽，不弹放大窗
      tile.addEventListener('click', () => { if (chart.movedPx <= 5) V.openTrendDialog(session, t); });
      tile._chart = chart;
      host.appendChild(tile);
    }

    // flame
    const flameHost = document.getElementById('dtFlame');
    if (flameHost._flame) flameHost._flame.destroy();
    flameHost.textContent = '';
    const flw = V.buildFlameWidget(cache.parsed);
    flameHost._flame = flw._flame;
    flameHost.appendChild(flw);

    // hot tables
    const hotHost = document.getElementById('dtHot');
    hotHost.textContent = '';
    V.renderHotTables(hotHost, cache.hot, cache.series);
  };

  // 点击小方块 → 弹窗放大查看单个趋势（全高交互图）
  // 通用「点击小方块 → 全尺寸弹窗」：总览面板与 DEEP 趋势共用。
  // opts: { link, height }
  V.openChartDialog = function (session, title, lines, opts) {
    opts = opts || {};
    let dlg = document.getElementById('dlgTrend');
    if (!dlg) {
      dlg = document.createElement('dialog');
      dlg.id = 'dlgTrend';
      document.body.appendChild(dlg);
    }
    dlg.textContent = '';
    const titleEl = V.el('h3', {}, title);
    const close = V.el('button', { class: 'dlg-close' }, '✕');
    close.addEventListener('click', () => dlg.close());
    const canvas = document.createElement('canvas');
    const chart = new V.TChart(canvas, { link: opts.link || V.ensurePanelLink(),
                                          height: opts.height || 460,
                                          events: session.events, bands: session.bands,
                                          wall: session.wall });
    for (const line of lines) {
      chart.addSeries({ id: line.id, label: line.label, x: line.x, y: line.y,
                       scale: line.scale || 'left', unit: line.unit, scaleName: line.scaleName,
                       kind: line.kind });
    }
    dlg.appendChild(V.el('div', { class: 'dlg-head' }, [titleEl, close]));
    dlg.appendChild(chart.wrap);
    V.showDialog(dlg);
    dlg.addEventListener('close', () => { chart.destroy(); dlg.textContent = ''; }, { once: true });
  };

  // DEEP 趋势小方块放大（沿用深联动组）
  V.openTrendDialog = function (session, t) {
    V.openChartDialog(session, t.label, t.lines, { link: V.ensureDeepLink(), height: 460 });
  };

  // 总览面板小方块放大（沿用面板联动组；面板编辑的高度沿用为弹窗高度）
  V.openPanelViewDialog = function (session, def) {
    V.openChartDialog(session, def.title, collectPanelLines(session, def),
                      { link: V.ensurePanelLink(), height: Math.max(def.height || 0, 320) });
  };
  // 逐线程趋势：每个细粒度指标一张图（cpu/切换/IO/缺页/锁/syscall/futex/runq），
  // 默认按全窗口 on_cpu 增量 Top-8 tid 展开；gap 处插断点。
  V.buildDeepTrends = function (session, series, gaps) {
    const out = [];
    const entries = [...series.values()];
    const rankKey = 'on_cpu_ns';
    const ranked = entries.map((t) => {
      let total = 0;
      for (let i = 1; i < t.x.length; i++) total += Math.max(0, t.raw[rankKey][i] - t.raw[rankKey][i - 1]);
      return { t, total };
    }).sort((a, b) => b.total - a.total);
    const top8 = ranked.slice(0, 8).map((r) => r.t.tid);
    const gapXs = gaps.map((g) => (g.ts_ns - session.t0) / 1e9);

    for (const metric of V.DEEP_METRICS) {
      const expr = (d, t) => metric.expr(d, t);
      const agg = V.aggregate(entries, { mode: 'tid', sel: top8 }, expr);
      const lines = agg.lines.map((l) => ({
        id: 'tid:' + l.tid, label: (l.comm || 'tid') + ' (' + l.tid + ')',
        x: l.x, y: l.y, gaps: gapXs, unit: metric.unit, scaleName: metric.scaleName,
      }));
      if (!lines.length) continue;
      out.push({ label: metric.label, unit: metric.unit, lines });
    }
    return out;
  };

  // flame widget with pid/tid filter + search
  V.buildFlameWidget = function (parsed) {
    const wrap = V.el('div', {});
    const toolbar = V.el('div', { class: 'bar' },
      [V.el('span', {}, '数据集:'),
       V.el('button', { id: 'flKindOn', class: 'active' }, 'on-cpu'),
       V.el('button', { id: 'flKindOff' }, 'off-cpu'),
       V.el('select', { id: 'flPid' }, [V.el('option', { value: '' }, '进程: 全部')]),
       V.el('select', { id: 'flTid' }, [V.el('option', { value: '' }, '线程: 全部')]),
       V.el('input', { id: 'flSearch', placeholder: '搜索帧…', style: 'width:160px' }),
       V.el('button', { id: 'flReset' }, '重置')]);
    wrap.appendChild(toolbar);
    const crumbs = V.el('div', { id: 'flameBreadcrumb' }, [V.el('span', {}, '全部')]);
    wrap.appendChild(crumbs);
    const canvas = document.createElement('canvas');
    canvas.id = 'flameCanvas';
    canvas.width = 900; canvas.height = 240;
    wrap.appendChild(canvas);
    const status = V.el('div', { id: 'flameStatus' }, '');
    const hover = V.el('div', { id: 'flameHover' }, '');
    wrap.appendChild(status);
    wrap.appendChild(hover);

    let kind = 'on_cpu';
    let flame = new V.Flame(canvas, { data: parsed[kind], unit: kind === 'on_cpu' ? 'samples' : 'ns',
                                       filter: { pid: null, tid: null } });
    flame.statusEl = status; flame.hoverEl = hover;
    const crumbEl = crumbs;
    // 下钻/返回/重置后同步面包屑 UI
    flame.onFocus = () => refreshCrumbs();

    const refreshCrumbs = () => {
      crumbs.textContent = '';
      const all = V.el('button', {}, '全部');
      all.addEventListener('click', () => { flame.reset(); refreshCrumbs(); });
      crumbs.appendChild(all);
      for (const b of flame.breadcrumb) {
        const bd = V.el('button', {}, b.name);
        bd.addEventListener('click', () => { flame.upTo(b); refreshCrumbs(); });
        crumbs.appendChild(V.el('span', {}, ' > '));
        crumbs.appendChild(bd);
      }
      const focus = flame.focus;
      if (focus && focus !== flame.root) {
        crumbs.appendChild(V.el('span', {}, ' (' + focus.value + '/' + flame.data.total + ')'));
      }
    };
    flame._emitStatus = (t) => { status.textContent = t; };

    const rebuild = () => {
      flame.setData(parsed[kind], kind === 'on_cpu' ? 'samples' : 'ns');
      flame.statusEl = status; flame.hoverEl = hover;
      flame._emitStatus = (t) => { status.textContent = t; };
      refreshCrumbs();
    };
    wrap._flame = flame;

    // local element refs (widget subtree may not be attached to document yet)
    const kindOn = toolbar.querySelector('#flKindOn');
    const kindOff = toolbar.querySelector('#flKindOff');
    const pidSel = toolbar.querySelector('#flPid');
    const tidSel = toolbar.querySelector('#flTid');
    const searchIn = toolbar.querySelector('#flSearch');
    const resetBtn = toolbar.querySelector('#flReset');
    kindOn.addEventListener('click', () => {
      kind = 'on_cpu'; rebuild();
      kindOn.classList.add('active');
      kindOff.classList.remove('active');
    });
    kindOff.addEventListener('click', () => {
      kind = 'off_cpu'; rebuild();
      kindOff.classList.add('active');
      kindOn.classList.remove('active');
    });

    const data = parsed[kind];
    const pids = [...data.pids.entries()].sort((a, b) => b[1].total - a[1].total);
    const tids = [...data.tids.entries()].sort((a, b) => b[1].total - a[1].total);
    const anyNull = data.lines.some((l) => !l.p || !l.t);
    if (anyNull) pidSel.appendChild(V.el('option', { value: '__null' }, '（无归属）'));
    for (const [pid, e] of pids) {
      const pct = data.total ? (e.total / data.total * 100).toFixed(1) : '0';
      pidSel.appendChild(V.el('option', { value: String(pid) }, `${e.comm || ''} (pid ${pid}) — ${pct}%`));
    }
    for (const [tid, e] of tids) {
      const pct = data.total ? (e.total / data.total * 100).toFixed(1) : '0';
      tidSel.appendChild(V.el('option', { value: String(tid) }, `${e.comm || ''} (tid ${tid}) — ${pct}%`));
    }
    pidSel.addEventListener('change', () => {
      const v = pidSel.value;
      flame.setFilter({ pid: v === '' ? null : v === '__null' ? -1 : Number(v), tid: flame.filter.tid });
      refreshCrumbs();
    });
    tidSel.addEventListener('change', () => {
      flame.setFilter({ pid: flame.filter.pid, tid: tidSel.value === '' ? null : Number(tidSel.value) });
      refreshCrumbs();
    });
    searchIn.addEventListener('input', (e) => {
      flame.setSearch(e.target.value);
      flame._emitStatus = (t) => { status.textContent = t; };
    });
    resetBtn.addEventListener('click', () => {
      pidSel.value = ''; tidSel.value = '';
      searchIn.value = '';
      flame.setFilter({ pid: null, tid: null });
      flame.reset();
      refreshCrumbs();
    });

    rebuild();
    return wrap;
  };

  // hot tables with sort + filter; seriesMap: tid -> {tid,comm,tgid} (deep_series)
  V.renderHotTables = function (host, hot, seriesMap) {
    // tid -> {tgid, comm}；tgid -> 进程名（主线程 comm 优先）
    const tidInfo = new Map();
    const pidInfo = new Map();
    for (const s of (seriesMap || new Map()).values()) {
      tidInfo.set(s.tid, { tgid: s.tgid, comm: s.comm });
      let p = pidInfo.get(s.tgid);
      if (!p) { p = { main: s.comm }; pidInfo.set(s.tgid, p); }
      if (s.tid === s.tgid) p.main = s.comm;
    }
    const enrich = (rows) => rows.map((r) => {
      const ti = tidInfo.get(Number(r.tid));
      const pname = ti ? (pidInfo.get(ti.tgid) || {}).main : '';
      return Object.assign({}, r, {
        pid: ti ? ti.tgid : null,
        pname: pname || '',
        tname: ti ? ti.comm : '',
      });
    });
    // pid 筛选（用户手动指定查看的进程；lock/iofile 为全局级，不参与）
    const pidSel = V.el('select', { id: 'hotPid' }, [V.el('option', { value: '' }, '全部进程')]);
    for (const [tgid, p] of [...pidInfo.entries()].sort((a, b) => a[0] - b[0])) {
      pidSel.appendChild(V.el('option', { value: String(tgid) },
        `${p.main || ''} (pid ${tgid})`));
    }
    host.appendChild(V.el('div', { class: 'bar' }, [V.el('label', {}, '进程筛选:'), pidSel]));
    const pidFilter = () => (pidSel.value === '' ? null : Number(pidSel.value));
    pidSel.addEventListener('change', () => {
      for (const ev of host.querySelectorAll('.hot-section')) ev.dataset.dirty = '1';
      host.querySelectorAll('.hot-section').forEach((sec) => {
        if (sec._draw) sec._draw();
      });
    });
    const config = [
      { key: 'syscall', title: '系统调用热点', withTid: true,
        cols: [['pid', 'pid', 'num'], ['pname', '进程名', 'txt'],
               ['tid', 'tid', 'num'], ['tname', '线程名', 'txt'],
               ['syscall', '系统调用号', 'num'], ['name', '系统调用名', 'txt'],
               ['count', '次数', 'num'], ['avg_us', '均时us', 'num'],
               ['p50_us', 'p50us', 'num'], ['p99_us', 'p99us', 'num'],
               ['error_count', '错误数', 'num']] },
      { key: 'runq', title: '调度延迟', withTid: true,
        cols: [['pid', 'pid', 'num'], ['pname', '进程名', 'txt'],
               ['tid', 'tid', 'num'], ['tname', '线程名', 'txt'],
               ['count', '次数', 'num'], ['avg_us', '均时us', 'num'],
               ['p50_us', 'p50us', 'num'], ['p99_us', 'p99us', 'num']] },
      { key: 'lock', title: '锁竞争（全局）', withTid: false,
        cols: [['addr', '地址', 'txt'], ['sym', '符号', 'txt'],
               ['count', '次数', 'num'], ['total_wait_ns', '总等待ns', 'num'],
               ['avg_wait_ns', '均等ns', 'num']] },
      { key: 'iofile', title: 'IO 文件（全局）', withTid: false,
        cols: [['path', '路径', 'txt'], ['dev', 'dev', 'num'],
               ['ino', 'ino', 'num'], ['bytes', '字节', 'num'], ['ops', '次数', 'num'],
               ['errors', '错误', 'num'], ['p50_us', 'p50us', 'num'],
               ['p99_us', 'p99us', 'num']] },
      { key: 'proc', title: '进程证据', withTid: false,
        cols: [['tid', 'tid', 'num'], ['comm', '进程名', 'txt'],
               ['vm_rss_kb', 'RSS(kB)', 'num'], ['rss_anon_kb', '匿名(kB)', 'num'],
               ['rss_file_kb', '文件(kB)', 'num'], ['rss_shmem_kb', '共享(kB)', 'num'],
               ['vm_swap_kb', 'Swap(kB)', 'num'], ['read_bytes', '读字节', 'num'],
               ['write_bytes', '写字节', 'num'], ['sched_run_delay_ns', '调度延迟ns', 'num'],
               ['sched_switch_count', '切换次数', 'num']] },
      { key: 'iodev', title: '设备 IO（DEEP）', withTid: false,
        cols: [['dev', 'dev', 'num'], ['ops', '次数', 'num'], ['bytes', '字节', 'num'],
               ['lat_sum', '总时延ns', 'num'], ['p50_us', 'p50us', 'num'],
               ['p99_us', 'p99us', 'num']] },
      { key: 'netflow', title: '网络连接流', withTid: true,
        cols: [['pid', 'pid', 'num'], ['pname', '进程名', 'txt'],
               ['tid', 'tid', 'num'], ['local_port', '本地端口', 'num'],
               ['remote_port', '远端端口', 'num'], ['final_state', '状态', 'num'],
               ['connect_latency_us', '建连时延us', 'num'], ['duration_us', '时长us', 'num'],
               ['tx_bytes', '发送字节', 'num'], ['rx_bytes', '接收字节', 'num'],
               ['retransmits', '重传', 'num'], ['rtt_avg_us', 'RTT均值us', 'num'],
               ['closed', '已关闭', 'num']] },
      { key: 'netdrop', title: '丢包证据', withTid: false,
        cols: [['netns_ino', 'netns', 'num'], ['ifindex', '接口', 'num'],
               ['reason_id', '原因', 'num'], ['reason', '说明', 'txt'],
               ['count', '次数', 'num']] },
      { key: 'netsoft', title: '网络软中断', withTid: false,
        cols: [['cpu_idx', 'CPU', 'num'], ['vector_name', '向量', 'txt'],
               ['count', '次数', 'num'], ['time_ns', '耗时ns', 'num']] },
      { key: 'gpuproc', title: 'GPU 进程', withTid: false,
        cols: [['pid', 'pid', 'num'], ['tgid', 'tgid', 'num'],
               ['gpu_uuid', 'GPU', 'txt'], ['comm', '进程名', 'txt'],
               ['sm_util_pct', 'SM%', 'num'], ['mem_util_pct', '显存%', 'num'],
               ['fb_used_bytes', '显存字节', 'num']] },
      { key: 'offcpu', title: '离CPU等待（无栈）', withTid: false,
        cols: [['tid', 'tid', 'num'], ['comm', '线程名', 'txt'],
               ['dwell_ns', '等待ns', 'num'], ['count', '次数', 'num'],
               ['stack_available', '有栈', 'num']] },
    ];
    for (const c of config) {
      let rows = (hot[c.key] || []).slice();
      if (c.key === 'iofile') {
        // aggregate by path
        const m = new Map();
        for (const r of rows) {
          const k = r.path;
          if (!m.has(k)) m.set(k, { path: k, bytes: 0, ops: 0, errors: 0, dev: r.dev, ino: r.ino });
          m.get(k).bytes += r.bytes; m.get(k).ops += r.ops; m.get(k).errors += r.errors;
        }
        rows.length = 0; rows.push(...m.values());
      }
      if (c.withTid) rows = enrich(rows);   // pid/pname/tname 三列
      const section = V.el('div', { class: 'hot-section' },
        [V.el('h4', {}, c.title + ' (' + rows.length + ')'),
         V.el('input', { class: 'hfilter', placeholder: '过滤…' }),
         V.el('div', { class: 'htable-wrap' })]);
      host.appendChild(section);
      const wrap = section.querySelector('.htable-wrap');
      const filterIn = section.querySelector('.hfilter');
      let sortKey = c.cols[0][0], sortDesc = true;
      const draw = () => {
        let data = rows.slice();
        if (c.withTid) {
          const pf = pidFilter();
          if (pf != null) data = data.filter((r) => r.pid === pf);
        }
        const q = filterIn.value.trim().toLowerCase();
        if (q) data = data.filter((r) => Object.values(r).some((v) => String(v ?? '').toLowerCase().includes(q)));
        data.sort((a, b) => {
          const av = a[sortKey], bv = b[sortKey];
          const num = typeof av === 'number' && typeof bv === 'number';
          if (av == null) return 1; if (bv == null) return -1;
          return num ? (sortDesc ? bv - av : av - bv)
                     : sortDesc ? String(bv).localeCompare(String(av)) : String(av).localeCompare(String(bv));
        });
        wrap.textContent = '';
        const tbl = V.el('table', { class: 'htable' });
        const thead = V.el('tr', {}, c.cols.map(([k, label]) => {
          const th = V.el('th', {}, label);
          th.addEventListener('click', () => {
            if (sortKey === k) sortDesc = !sortDesc; else { sortKey = k; sortDesc = true; }
            draw();
          });
          return th;
        }));
        tbl.appendChild(V.el('thead', {}, thead));
        const tbody = V.el('tbody', {});
        for (const r of data) {
          tbody.appendChild(V.el('tr', {}, c.cols.map(([k, , type]) =>
            V.el('td', { class: type === 'num' ? 'num' : '' }, type === 'num' ? V.fmt.num(r[k], 2) : (r[k] ?? '')))));
        }
        tbl.appendChild(tbody);
        wrap.appendChild(tbl);
      };
      section._draw = draw;
      filterIn.addEventListener('input', draw);
      draw();
    }
  };

  // ------------------------------------------------------------------
  // Logs tab
  // ------------------------------------------------------------------
  V.renderLogsTab = function (session) {
    const ctl = document.getElementById('logCtl');
    ctl.textContent = '';
    const levels = ['INFO', 'WARN', 'ERROR', 'DEBUG'];
    const active = new Set(levels);
    const chips = levels.map((lv) => {
      const c = V.el('button', { class: 'chip on' }, lv);
      c.addEventListener('click', () => {
        if (active.has(lv)) { active.delete(lv); c.classList.remove('on'); } else { active.add(lv); c.classList.add('on'); }
        redraw();
      });
      return c;
    });
    const search = V.el('input', { placeholder: '搜索…', style: 'width:220px' });
    const countEl = V.el('span', {}, '');
    ctl.append(...chips, search, countEl);

    const logHost = document.getElementById('logView');
    logHost.textContent = '';

    const rows = session.logs; // [{seq, line, time, level, msg}]
    const render = () => {
      const q = search.value.trim().toLowerCase();
      const shown = [];
      for (const r of rows) {
        if (!active.has(r.level)) continue;
        if (q && !r.line.toLowerCase().includes(q)) continue;
        shown.push(r);
      }
      countEl.textContent = `显示 ${Math.min(shown.length, 20000)} / ${rows.length} 行`;
      logHost.textContent = '';
      const limited = shown.slice(0, 20000);
      for (const r of limited) {
        const t = r.time ? r.time.slice(11, 23) : '';
        const row = V.el('div', { class: 'log-line' },
          [V.el('span', { class: 'log-ts' }, t),
           V.el('span', { class: 'lv-' + r.level }, r.level),
           V.el('span', { class: 'log-msg' }, r.msg)]);
        const btn = V.el('button', {}, '定位到图表时段');
        btn.addEventListener('click', () => {
          const t = session.logTime(r); // wall time ms
          if (t == null) return;
          const anchor = session.wall.anchor;
          if (!anchor) return;
          const x = (t - anchor.getTime()) / 1000;   // 图表 x 域 = 距锚点的秒数
          // 锚点偏差告警：日志墙钟-锚点若为负或远超会话时长，说明目录名锚点不可靠
          if (!isFinite(x)) return;
          // 确保联动开启（否则 set 只落到各图自身视口）并保持 checkbox 与持久化状态一致
          const chk = document.getElementById('chkLink');
          chk.checked = true;
          V.panels.state.linkX = true;
          V.panels.saveSoon();
          V.ensurePanelLink().set(x - 30, x + 60);
          V.switchTab('dash');
        });
        row.appendChild(btn);
        logHost.appendChild(row);
      }
      if (shown.length > 20000) logHost.appendChild(V.el('div', { class: 'log-line' },
        V.el('span', { class: 'log-msg' }, '… 已截断，仅显示前 20000 行')));
    };
    const redraw = V.debounce(render, 150);
    search.addEventListener('input', redraw);
    render();
  };
})(typeof window !== 'undefined' ? window : globalThis);
