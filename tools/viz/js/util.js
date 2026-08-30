/* eTrace-Diag viz — shared utilities (window.V namespace). */
(function (global) {
  'use strict';
  const V = global.V = global.V || {};

  // ---- formatting ----
  V.fmt = {
    bytes(n) {
      if (!isFinite(n) || n == null) return '—';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      let v = n, u = 0;
      while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
      return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + ' ' + units[u];
    },
    num(n, digits) {
      if (n == null || !isFinite(n)) return '—';
      const d = digits == null ? (Math.abs(n) >= 100 ? 1 : 2) : digits;
      return n.toFixed(d);
    },
    pct(n) {
      if (n == null || !isFinite(n)) return '—';
      return n.toFixed(1) + '%';
    },
    // scale -> unit suffix (see METRICS scale registry)
    unitOf(scale) {
      const map = { pct: '%', count: '个', rate: '次/s', mb: 'MB', mbps: 'MB/s',
        ms: 'ms', load: 'load', bool: '0/1' };
      return map[scale] || '';
    },
    // wall clock HH:MM:SS from a Date
    hms(d) {
      if (!d || isNaN(d.getTime())) return '—';
      const p = (x) => String(x).padStart(2, '0');
      return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    },
    // relative seconds "+12.345s"
    rel(sec) {
      if (sec == null || !isFinite(sec)) return '';
      const s = sec < 0 ? '-' : '+';
      return s + Math.abs(sec).toFixed(3) + 's';
    },
  };

  // ---- misc ----
  V.debounce = function (fn, ms) {
    let t = null;
    return function (...args) {
      if (t) clearTimeout(t);
      t = setTimeout(() => { t = null; fn.apply(this, args); }, ms);
    };
  };

  // build element with optional props/children (text strings become Text nodes)
  V.el = function (tag, attrs, children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === 'class') el.className = v;
        else if (k === 'style') el.style.cssText = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else if (v != null) el.setAttribute(k, v);
      }
    }
    if (children) {
      for (const c of [].concat(children)) {
        if (c == null) continue;
        el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      }
    }
    return el;
  };

  // dialog 打开兼容：支持 showModal 用模态；否则退化为 open 属性（jsdom/旧浏览器）
  V.showDialog = function (dlg) {
    if (typeof dlg.showModal === 'function') dlg.showModal();
    else dlg.setAttribute('open', '');
  };

  // linear-ish string hash (used for pid -> hue)
  V.hashInt = function (n) {
    let h = (n >>> 0) * 2654435761 % 2 ** 31;
    h = ((h ^ (h >>> 16)) * 2246822519) % 2 ** 31;
    return h >>> 0;
  };
})(typeof window !== 'undefined' ? window : globalThis);
