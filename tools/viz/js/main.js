/* eTrace-Diag viz — bootstrap: session discovery, loading, tabs, panel dialog. */
(function () {
  'use strict';
  const V = window.V;
  const $ = (id) => document.getElementById(id);
  const sessions = new Map(); // name -> File

  // 会话输出根目录（服务器根绝对路径）。页面可能位于 /tools/viz/ 子路径，
  // 因此 fetch 一律用以 '/' 开头的绝对 URL，避免相对路径按页面基准错解析。
  //   index.html?out=/out           （默认，映射到服务器 /out/）
  //   index.html?out=/data/runs     （任意服务器根下的输出目录）
  const DEFAULT_OUT = '/out';

    // 列出输出目录下所有会话（HTTP 目录列表 → 解析 <a href="dir/"> 链接 →
  // 逐个探测 etrace.sqlite3 存在）。返回 [{name, dir}]，按名称倒序（最新在前）。
  async function listSessions(out) {
    const status = $('lblStatus');
    status.textContent = '扫描输出目录 ' + out + ' …';
    status.className = '';
    try {
      const res = await fetch(out + '/');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const html = await res.text();
      // python http.server 目录列表：<a href="<dir>/">（或 <li><a href="...">）
      const dirs = [...html.matchAll(/<a href="([^"#?]+)\/"/g)].map((m) => m[1]);
      const names = [...new Set(dirs)].filter((d) => /^\d{8}-\d{6}_\d+$/.test(d));
      const found = [];
      for (const name of names.sort().reverse()) {
        const probe = await fetch(out + '/' + name + '/etrace.sqlite3', { method: 'HEAD' });
        if (probe.ok) found.push(name);
      }
      return found;
    } catch (e) {
      console.warn('listSessions failed:', out, e);
      status.textContent = '无法列出输出目录 ' + out + '（' + (e && e.message ? e.message : e) +
        '）。请用内置服务启动：python3 tools/viz/serve.py（同时服务页面与 /out/）；' +
        '或用 ?out=<路径> 指定可访问的输出目录。';
      status.className = 'warn';
      return null;
    }
  }

  // 启动：发现输出目录会话 → 填充下拉 → 默认选中最新会话并加载。
  async function bootFromOutputDir() {
    let out = new URLSearchParams(location.search).get('out') || DEFAULT_OUT;
    if (!out.startsWith('/')) out = '/' + out;  // 统一为服务器根绝对路径
    const label = out === '/' ? '/' : out.replace(/\/+$/, '');
    const names = await listSessions(out);
    if (!names) return; // 已提示
    if (!names.length) {
      $('lblStatus').textContent = '输出目录 ' + label + ' 下未发现会话（含 etrace.sqlite3）';
      $('lblStatus').className = 'warn';
      $('selSession').disabled = true;
      return;
    }
    for (const name of names) {
      // 登记但暂不下载：选中时 fetch 加载
      sessions.set(name, { out, name });
      const sel = $('selSession');
      sel.appendChild(V.el('option', { value: name }, name));
    }
    $('selSession').disabled = false;
    $('btnReload').disabled = false;
    $('lblStatus').textContent = '输出目录 ' + label + '：发现 ' + names.length + ' 个会话';
    $('lblStatus').className = '';
    // 默认选中最新会话（名称倒序第一个）
    await loadSession(names[0]);
  }

  // ------------------------------------------------------------------
  // Session loading
  // ------------------------------------------------------------------
  let current = null; // {db, file, store, enums, events, bands, t0, wall, ...}

  $('selSession').addEventListener('change', (e) => loadSession(e.target.value));
  async function loadSession(name) {
    let file = sessions.get(name);
    if (!file) return;
    // 输出目录发现的会话：文件未下载，按 out/<name>/etrace.sqlite3 惰性 fetch
    if (!(file instanceof File)) {
      const status0 = $('lblStatus');
      status0.textContent = '下载 ' + name + ' …';
      try {
        const res = await fetch(file.out + '/' + file.name + '/etrace.sqlite3');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const buf = await res.arrayBuffer();
        file = new File([buf], 'etrace.sqlite3');
        sessions.set(name, file);
      } catch (e) {
        console.error(e);
        status0.textContent = '下载会话失败 ' + name + ': ' + (e && e.message ? e.message : e);
        status0.className = 'err';
        return;
      }
    }
    if (file.size > 512 * 1024 * 1024) {
      if (!confirm('数据库较大（>512MB），继续加载可能耗内存，确定？')) return;
    }
    const status = $('lblStatus');
    status.textContent = '加载 ' + name + ' …';
    status.className = '';
    try {
      const db = await V.db.open(file);
      // schema_version check
      const ver = V.db.scalar(db, "SELECT value FROM meta WHERE key='schema_version'");
      if (ver !== '1') {
        status.textContent = 'DB 版本不支持 (schema_version=' + ver + ')';
        status.className = 'err';
        return;
      }
      const extracted = V.extract(db);
      // wall anchor: parse session dir name as local Date minus t0
      const anchor = parseDirTime(name);
      const logs = [];
      V.db.step(db, 'SELECT seq,line FROM logs ORDER BY seq', null, (r) => {
        const m = /^\[(.*?)\] \[(\w+)\] (.*)$/.exec(r.line);
        if (m) logs.push({ seq: r.seq, line: r.line, time: m[1], level: m[2], msg: m[3] });
        else if (logs.length) {
          // continuation line -> merge into previous
          logs[logs.length - 1].msg += '\n' + r.line;
          logs[logs.length - 1].line += '\n' + r.line;
        } else logs.push({ seq: r.seq, line: r.line, time: null, level: 'INFO', msg: r.line });
      });

      const episodes = V.db.query(db, 'SELECT ordinal,meta_json,summary_text FROM deep_episodes ORDER BY ordinal').map((ep) => {
        let startWall = null, dur = null, running = false, start = null, end = null;
        if (ep.meta_json) {
          try {
            const m = JSON.parse(ep.meta_json);
            start = m.anomaly_start_ts; end = m.anomaly_end_ts;
            startWall = anchor && start != null ? V.fmt.hms(new Date(anchor.getTime() + (start - extracted.t0) / 1e9 * 1000)) : null;
            dur = start != null && end != null ? ((end - start) / 1e9).toFixed(0) : null;
          } catch (e) { /* ignore */ }
        }
        if (end == null || end === 0) running = true;
        return { ordinal: ep.ordinal, startWall, dur, running };
      });
      // running deep episode: meta_json NULL OR anomaly_end_ts 0
      const runningEp = V.db.query(db, 'SELECT ordinal FROM deep_episodes WHERE meta_json IS NULL ORDER BY ordinal DESC LIMIT 1');
      const runningDeep = runningEp.length ? runningEp[0].ordinal : null;
      const runningMeta0 = V.db.query(db, 'SELECT ordinal,meta_json FROM deep_episodes WHERE meta_json IS NOT NULL ORDER BY ordinal DESC LIMIT 5');
      let runningDeep2 = null;
      for (const r of runningMeta0) {
        try {
          const m = JSON.parse(r.meta_json);
          if (m.anomaly_end_ts == null || m.anomaly_end_ts === 0) { runningDeep2 = r.ordinal; break; }
        } catch (e) { /* ignore */ }
      }

      current = {
        name, file, db, store: extracted.store, enums: extracted.enums,
        events: extracted.events, bands: extracted.bands, t0: extracted.t0,
        tidRaw: extracted.tidRaw, logs, episodes,
        wall: { anchor },   // 图表 x 域 = 距锚点秒数（帆 extracted 已减过 t0）
        runningDeep: runningDeep != null ? runningDeep : runningDeep2,
        logTime: (r) => {
          if (!r.time) return null;
          return new Date(r.time).getTime();
        },
      };
      // clear deep cache on session (re)load
      V.deepCache = {};

      // ---- render ----
      V.panels.load();
      $('chkLink').checked = V.panels.state.linkX;
      $('chkEvents').checked = V.panels.state.showEvents;
      V.renderCards(current);
      V.renderPanelHost(current);
      V.renderDeepTab(current);
      V.renderLogsTab(current);

      status.textContent = '已加载 ' + name + '（host 行数=' + extracted.store.get('host.cpu.usage_pct')?.y.length + '）';
      status.className = '';
    } catch (e) {
      console.error(e);
      status.textContent = '加载失败: ' + (e && e.message ? e.message : e);
      status.className = 'err';
    }
  }

  function parseDirTime(name) {
    // name = YYYYmmdd-HHMMSS_pid
    const m = /^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})_/.exec(name);
    if (!m) return null;
    const [, Y, Mo, D, H, Mi, S] = m.map(Number);
    return new Date(Y, Mo - 1, D, H, Mi, S);
  }

  // ------------------------------------------------------------------
  // Tabs
  // ------------------------------------------------------------------
  V.switchTab = function (tab) {
    for (const b of document.querySelectorAll('#tabs button')) b.classList.toggle('active', b.dataset.tab === tab);
    $('tab-dash').hidden = tab !== 'dash';
    $('tab-deep').hidden = tab !== 'deep';
    $('tab-logs').hidden = tab !== 'logs';
    // 打开 DEEP tab 时自动加载首个 episode（若尚未加载），火焰图/趋势立即就绪
    if (tab === 'deep' && current && !$('selEpisode').disabled) {
      const ord = Number($('selEpisode').value);
      if (ord && !V.deepCache[ord]) V.loadDeep(current, ord);
    }
  };
  document.querySelectorAll('#tabs button').forEach((b) => b.addEventListener('click', () => V.switchTab(b.dataset.tab)));
  document.querySelectorAll('#deepTabs button').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('#deepTabs button').forEach((x) => x.classList.toggle('active', x === b));
    $('dtSeries').hidden = b.dataset.dt !== 'series';
    $('dtFlame').hidden = b.dataset.dt !== 'flame';
    $('dtHot').hidden = b.dataset.dt !== 'hot';
  }));

  $('btnLoadDeep').addEventListener('click', () => {
    if (!current) return;
    const ord = Number($('selEpisode').value);
    if (!ord) return;
    V.loadDeep(current, ord);
    // switch to series sub-tab
    document.querySelectorAll('#deepTabs button').forEach((x) => x.classList.toggle('active', x.dataset.dt === 'series'));
    $('dtSeries').hidden = false; $('dtFlame').hidden = true; $('dtHot').hidden = true;
  });

  // link/events toggles persist
  $('chkLink').addEventListener('change', () => { V.panels.state.linkX = $('chkLink').checked; V.panels.saveSoon(); });
  $('chkEvents').addEventListener('change', () => {
    V.panels.state.showEvents = $('chkEvents').checked;
    V.panels.saveSoon();
    // draw() 内部动态读取该开关，重绘即可 —— 保留各图缩放视口
    for (const c of V.allCharts) c.requestRedraw();
  });

  // ------------------------------------------------------------------
  // Panel import/export
  // ------------------------------------------------------------------
  $('btnExport').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(V.panels.state, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'etrace-viz-panels.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $('btnImport').addEventListener('click', () => $('fileImport').click());
  $('fileImport').addEventListener('change', (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => {
      try {
        V.panels.importJSON(rd.result);
        if (current) V.renderPanelHost(current);
        // 导入会覆盖 linkX/showEvents —— 同步顶栏开关，避免 UI 与持久化状态脱节
        $('chkLink').checked = V.panels.state.linkX;
        $('chkEvents').checked = V.panels.state.showEvents;
        $('lblStatus').textContent = '面板已导入';
        $('lblStatus').className = '';
      } catch (err) {
        alert('导入失败: ' + err.message);
      }
    };
    rd.readAsText(f);
    e.target.value = '';
  });

  // ------------------------------------------------------------------
  // Panel edit dialog (step 8.4)
  // ------------------------------------------------------------------
  V.openPanelDialog = function (session, def) {
    const dlg = $('dlgPanel');
    dlg.textContent = '';
    const isNew = !def;
    const editing = def || { id: 'p' + Math.random().toString(36).slice(2, 8), title: '', height: 220,
                             kind: 'line', series: [] };
    const st = V.panels.state;

    // ---- data source selectors ----
    const sources = [
      ['host', '主机'],
      ['anomaly', '目标计数'],
      ['proc_overhead', '采集器'],
      ['bpf_stats', 'BPF程序'],
      ['io_devices', '块设备'],
      ['memory_events', '内存事件'],
      ['ebpf_tid', '目标线程'],
      ['host_proc', '进程'],
    ];
    const srcSel = V.el('select', {}, sources.map(([v, l]) => V.el('option', { value: v }, l)));
    const familySel = V.el('select', {});
    const paramSel = V.el('select', {});

    // family options per source
    const famOf = (src) => {
      if (src === 'host') return [
        ['host.cpu.usage_pct', 'CPU 利用率 (%)'], ['host.cpu.user_pct', '用户态 (%)'],
        ['host.cpu.sys_pct', '内核态 (%)'], ['host.cpu.iowait_pct', 'IO 等待 (%)'],
        ['host.cpu.irq_pct', '中断 (%)'], ['host.load.load1', '负载1 (load)'],
        ['host.load.load5', '负载5 (load)'], ['host.load.load15', '负载15 (load)'],
        ['host.load.nr_running', '运行队列 (个)'], ['host.load.nr_threads', '线程总数 (个)'],
        ['host.mem.used_pct', '内存占用 (%)'], ['host.mem.cached_mb', '页缓存 (MB)'],
        ['host.mem.buffers_mb', '缓冲 (MB)'], ['host.mem.anon_mb', '匿名页 (MB)'],
        ['host.mem.avail_mb', '可用内存 (MB)'], ['host.mem.swap_used_pct', 'Swap占用 (%)'],
        ['host.vm.pgfault_s', '缺页 (次/s)'], ['host.vm.pgmajfault_s', '主缺页 (次/s)'],
        ['host.vm.pswpin_s', '换入 (次/s)'], ['host.vm.pswpout_s', '换出 (次/s)'],
        ['host.psi.cpu.avg10', 'PSI cpu avg10 (%)'], ['host.psi.io.avg10', 'PSI io avg10 (%)'],
        ['host.psi.mem.avg10', 'PSI mem avg10 (%)'], ['host.psi.cpu.avg60', 'PSI cpu avg60 (%)'],
        ['host.psi.io.avg60', 'PSI io avg60 (%)'], ['host.psi.mem.avg60', 'PSI mem avg60 (%)'],
        ['host.psi.cpu.avg300', 'PSI cpu avg300 (%)'], ['host.psi.io.avg300', 'PSI io avg300 (%)'],
        ['host.psi.mem.avg300', 'PSI mem avg300 (%)'],
        ['host.cpu.core.*.usage_pct', '核利用率 (%) <参数>'], ['host.disk.*.util_pct', '盘繁忙度 (%) <参数>'],
        ['host.disk.*.read_mbs', '盘读 (MB/s) <参数>'], ['host.disk.*.write_mbs', '盘写 (MB/s) <参数>'],
        ['host.disk.*.read_await_ms', '盘读时延 (ms) <参数>'], ['host.disk.*.write_await_ms', '盘写时延 (ms) <参数>'],
      ];
      if (src === 'anomaly') return [
        ['ebpf.busy_pct', '目标线程总在核占比 (%)'], ['ebpf.switches_s', '切换 (次/s)'],
        ['ebpf.faults_s', '缺页 (次/s)'], ['ebpf.io_ops_s', 'IOPS (次/s)'],
        ['ebpf.io_mbs', 'IO吞吐 (MB/s)'], ['ebpf.lock_waits_s', '锁等待 (次/s)'],
      ];
      if (src === 'proc_overhead') return [
        ['ovh.cpu_pct', '采集器CPU (%)'], ['ovh.rss_mb', '采集器RSS (MB)'],
        ['ovh.vmhwm_mb', '采集器峰值 (MB)'], ['ovh.minflt_s', '次缺页 (次/s)'],
        ['ovh.majflt_s', '主缺页 (次/s)'], ['ovh.vcsw_s', '自愿切换 (次/s)'],
        ['ovh.ivcsw_s', '非自愿切换 (次/s)'],
      ];
      if (src === 'bpf_stats') return [['bpf.prog.*.runs_s', '程序调用 (次/s) <程序>'],
        ['bpf.prog.*.ms_per_s', '内核耗时 (ms/s) <程序>']];
      if (src === 'io_devices') return [['iodev.*.ops_s', '设备IOPS (次/s) <设备>'],
        ['iodev.*.mbs', '设备吞吐 (MB/s) <设备>'], ['iodev.*.await_ms', '设备时延 (ms) <设备>']];
      if (src === 'memory_events') return [
        ['memv.kswapd', 'kswapd 活动 (0/1)'], ['memv.direct_reclaim_s', '直接回收 (次/s)'],
        ['memv.nr_reclaimed_s', '回收页速率 (次/s)'],
      ];
      if (src === 'ebpf_tid') return [['ebpf.tid.*.cpu_pct', '线程在核占比 (%)'], ['ebpf.tid.*.io_ops_s', '线程IOPS'],
        ['ebpf.tid.*.fault_s', '线程缺页'], ['ebpf.tid.*.switch_s', '线程切换'], ['ebpf.tid.*.lock_s', '线程锁等待']];
      if (src === 'host_proc') return [['host.proc.*.cpu_pct', '进程CPU (%)'], ['host.proc.*.rss_mb', '进程RSS (MB)']];
      return [];
    };
    const rebuildFamilies = () => {
      familySel.textContent = '';
      for (const [v, l] of famOf(srcSel.value)) familySel.appendChild(V.el('option', { value: v }, l));
      rebuildParam();
    };
    const rebuildParam = () => {
      paramSel.textContent = '';
      const fam = familySel.value;
      const src = srcSel.value;
      const needParam = fam.includes('*') && src !== 'ebpf_tid' && src !== 'host_proc';
      paramSel.hidden = !needParam;
      if (!needParam) return;
      if (fam.startsWith('host.cpu.core.')) {
        for (const c of (session?.enums.cores || [])) paramSel.appendChild(V.el('option', { value: c }, '核 ' + c));
      } else if (fam.startsWith('host.disk.')) {
        for (const d of (session?.enums.disks || [])) paramSel.appendChild(V.el('option', { value: d }, d));
      } else if (fam.startsWith('bpf.prog.')) {
        for (const p of (session?.enums.bpfProgs || [])) paramSel.appendChild(V.el('option', { value: p }, p));
      } else if (fam.startsWith('iodev.')) {
        for (const d of (session?.enums.iodevs || [])) paramSel.appendChild(V.el('option', { value: d }, d));
      }
    };
    srcSel.addEventListener('change', rebuildFamilies);
    familySel.addEventListener('change', rebuildParam);

    // ---- series chips ----
    const chipsHost = V.el('div', { class: 'sel-chips' });
    const renderChips = () => {
      chipsHost.textContent = '';
      for (let i = 0; i < editing.series.length; i++) {
        const entry = editing.series[i];
        const label = entry.mid ? (entry.mid + (V.SCALES[V.scaleOf(entry.mid)] ? ' (' + V.SCALES[V.scaleOf(entry.mid)].unit + ')' : ''))
                                : (entry.family + ' · ' + entry.mode + ' · ' + (entry.sel ? entry.sel.length + ' 项' : ''));
        const chip = V.el('span', { class: 'sel-chip' },
          [label, V.el('button', {}, '×'), V.el('button', {}, '↑'), V.el('button', {}, '↓')]);
        chip.querySelectorAll('button')[0].addEventListener('click', () => { editing.series.splice(i, 1); renderChips(); });
        chip.querySelectorAll('button')[1].addEventListener('click', () => {
          if (i > 0) { const t = editing.series[i - 1]; editing.series[i - 1] = editing.series[i]; editing.series[i] = t; renderChips(); }
        });
        chip.querySelectorAll('button')[2].addEventListener('click', () => {
          if (i < editing.series.length - 1) { const t = editing.series[i + 1]; editing.series[i + 1] = editing.series[i]; editing.series[i] = t; renderChips(); }
        });
        chipsHost.appendChild(chip);
      }
    };

    // ---- add entry ----
    const addBtn = V.el('button', {}, '添加');
    addBtn.addEventListener('click', () => {
      const fam = familySel.value;
      const src = srcSel.value;
      const entry = {};
      if (src === 'ebpf_tid' || src === 'host_proc') {
        entry.family = fam;
        entry.mode = 'top';
        entry.sel = [5];
      } else {
        entry.mid = fam.includes('*') ? fam.replace('*', paramSel.value) : fam;
      }
      editing.series.push(entry);
      renderChips();
    });

    // ---- form ----
    const titleIn = V.el('input', { value: editing.title, style: 'width:220px' });
    const kindSel = V.el('select', {}, ['line', 'area', 'step'].map((k) => V.el('option', { value: k, selected: k === editing.kind ? '' : null }, k)));
    const heightIn = V.el('input', { type: 'number', value: editing.height, min: 120, max: 480, step: 20 });
    const dlgRow = (label, el) => V.el('div', { class: 'dlg-row' }, [V.el('label', {}, label), el]);

    dlg.appendChild(dlgRow('标题', titleIn));
    dlg.appendChild(dlgRow('类型', kindSel));
    dlg.appendChild(dlgRow('高度', heightIn));
    dlg.appendChild(dlgRow('已选序列', chipsHost));
    dlg.appendChild(dlgRow('数据源', srcSel));
    dlg.appendChild(dlgRow('指标', familySel));
    dlg.appendChild(dlgRow('参数', paramSel));
    dlg.appendChild(dlgRow('', addBtn));

    const btnRow = V.el('div', { class: 'dlg-row' },
      [V.el('button', { id: 'dlgOk' }, '保存'), V.el('button', { id: 'dlgCancel' }, '取消')]);
    dlg.appendChild(btnRow);

    const ok = dlg.querySelector('#dlgOk');
    const cancel = dlg.querySelector('#dlgCancel');

    const validate = () => {
      ok.disabled = !(titleIn.value.trim() && editing.series.length);
    };
    titleIn.addEventListener('input', validate);

    ok.addEventListener('click', () => {
      editing.title = titleIn.value.trim();
      editing.kind = kindSel.value;
      editing.height = Math.max(120, Math.min(480, Number(heightIn.value) || 220));
      if (isNew) st.panels.push(editing); else {
        const i = st.panels.findIndex((p) => p.id === editing.id);
        if (i >= 0) st.panels[i] = editing;
      }
      V.panels.saveSoon();
      if (current) V.renderPanelHost(current);
      dlg.close();
    });
    cancel.addEventListener('click', () => dlg.close());

    renderChips();
    rebuildFamilies();
    validate();
    dlg.showModal();
  };

  $('btnAddPanel').addEventListener('click', () => {
    if (!current) { alert('请先选择一个会话'); return; }
    V.openPanelDialog(current, null);
  });

  // ------------------------------------------------------------------
  // boot
  // ------------------------------------------------------------------
  V.panels.load();
  document.addEventListener('DOMContentLoaded', () => {
    V.switchTab('dash');
    // 启动：定位到输出目录 → 列出会话 → 默认选中最新（免目录选择器）
    bootFromOutputDir();
  });
})();