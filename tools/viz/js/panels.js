/* eTrace-Diag viz — panel system: state, localStorage persistence, edit dialog,
 * drag-drop ordering, import/export. Depends on V.TChart (chart.js).
 */
(function (global) {
  'use strict';
  const V = global.V = global.V || {};

  const LS_KEY = 'etrace-viz.v1';

  // ---- default panels (first-run seed) ----
  V.defaultPanels = () => [
    { id: 'p' + rid(), title: 'CPU 利用率', height: 220, kind: 'line',
      series: [{ mid: 'host.cpu.usage_pct' }, { mid: 'host.cpu.iowait_pct' }] },
    { id: 'p' + rid(), title: '负载与运行队列', height: 220, kind: 'line',
      series: [{ mid: 'host.load.load1' }, { mid: 'host.load.nr_running' }] },
    { id: 'p' + rid(), title: '内存', height: 200, kind: 'line',
      series: [{ mid: 'host.mem.used_pct' }, { mid: 'host.mem.swap_used_pct' }] },
    { id: 'p' + rid(), title: 'PSI 压力', height: 200, kind: 'line',
      series: [{ mid: 'host.psi.cpu.avg10' }, { mid: 'host.psi.io.avg10' }, { mid: 'host.psi.mem.avg10' }] },
    { id: 'p' + rid(), title: 'eBPF 目标热度', height: 220, kind: 'line',
      series: [{ mid: 'ebpf.busy_pct' }, { mid: 'ebpf.io_ops_s' }] },
    { id: 'p' + rid(), title: '采集器自开销', height: 200, kind: 'line',
      series: [{ mid: 'ovh.cpu_pct' }, { mid: 'ovh.rss_mb' }] },
    { id: 'p' + rid(), title: 'Top 进程 CPU', height: 220, kind: 'area',
      series: [{ family: 'host.proc.*.cpu_pct', mode: 'top', sel: [5] }] },
    { id: 'p' + rid(), title: 'BPF 程序开销', height: 220, kind: 'line',
      series: [{ mid: 'bpf.prog.on_switch.ms_per_s' }] },
    { id: 'p' + rid(), title: '网络重传', height: 180, kind: 'line',
      series: [{ mid: 'net.tcp.retrans_s' }, { mid: 'net.tcp.timeouts_s' }] },
    { id: 'p' + rid(), title: '网络流量', height: 180, kind: 'line',
      series: [{ family: 'net.iface.*.rx_mbps', mode: 'all', sel: [] },
               { family: 'net.iface.*.tx_mbps', mode: 'all', sel: [] }] },
    { id: 'p' + rid(), title: 'GPU 利用率', height: 180, kind: 'line',
      series: [{ family: 'gpu.*.util_pct', mode: 'all', sel: [] },
               { family: 'gpu.*.mem_pct', mode: 'all', sel: [] }] },
    { id: 'p' + rid(), title: 'cgroup 节流', height: 180, kind: 'line',
      series: [{ mid: 'cgroup.cpu_throttled_pct' }, { mid: 'cgroup.mem_current_mb' }] },
  ];

  function rid() { return Math.random().toString(36).slice(2, 8); }

  V.panels = {
    state: { version: 1, linkX: true, showEvents: true, panels: [] },

    load() {
      try {
        const raw = localStorage.getItem(LS_KEY);
        if (raw) {
          const st = JSON.parse(raw);
          if (st && st.version === 1 && Array.isArray(st.panels)) {
            V.panels.state = st;
            return;
          }
        }
      } catch (e) {
        console.warn('panel load:', e);
      }
      V.panels.state = { version: 1, linkX: true, showEvents: true, panels: V.defaultPanels() };
    },
    save() {
      try {
        localStorage.setItem(LS_KEY, JSON.stringify(V.panels.state));
      } catch (e) {
        console.warn('panel save:', e);
      }
    },
    _saveDebounced: null,
    saveSoon() {
      if (!V.panels._saveDebounced) {
        V.panels._saveDebounced = V.debounce(() => { V.panels.save(); }, 300);
      }
      V.panels._saveDebounced();
    },

    importJSON(text) {
      const st = JSON.parse(text);
      if (!st || st.version !== 1 || !Array.isArray(st.panels)) throw new Error('非法面板配置');
      V.panels.state = { version: 1, linkX: st.linkX !== false, showEvents: st.showEvents !== false,
                         panels: st.panels };
      V.panels.save();
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);