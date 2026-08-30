/* eTrace-Diag viz — flame graph: folded parser (pure) + canvas renderer. */
(function (global) {
  'use strict';
  const V = global.V = global.V || {};

  // classify a frame name for coloring
  V.classifyFrame = function (name) {
    if (!name) return 'kernel';
    if (name.startsWith('p:') || name.startsWith('t:')) return 'root';
    if (name.includes('/') || /^[0-9a-f]{6,}$/i.test(name) || name.startsWith('[anon]')) return 'user';
    return 'kernel';
  };

  // Parse folded text: "p:..;t:..;a;b;c <value>" per line.
  // Returns {lines, pids: Map<tgid,{comm,total}>, tids: Map<tid,{comm,tgid,total}>, total}
  V.parseFolded = function (text) {
    const out = { lines: [], pids: new Map(), tids: new Map(), total: 0 };
    if (!text) return out;
    for (const rawLine of String(text).split('\n')) {
      if (!rawLine) continue;
      const sp = rawLine.lastIndexOf(' ');
      if (sp < 0) continue;
      const framesStr = rawLine.slice(0, sp);
      const value = Number(rawLine.slice(sp + 1));
      if (!isFinite(value) || value <= 0) continue;
      const frames = framesStr.split(';').filter(Boolean);
      if (!frames.length) continue;

      const line = { frames, value, p: null, t: null };
      if (frames[0] && frames[0].startsWith('p:')) line.p = parsePT(frames[0]);
      if (frames[1] && frames[1].startsWith('t:')) line.t = parsePT(frames[1]);
      else if (frames[0] && frames[0].startsWith('t:')) line.t = parsePT(frames[0]);

      out.lines.push(line);
      out.total += value;

      if (line.p) {
        let e = out.pids.get(line.p.tgid);
        if (!e) { e = { comm: line.p.comm, total: 0 }; out.pids.set(line.p.tgid, e); }
        e.total += value;
      }
      if (line.t) {
        let e = out.tids.get(line.t.tid);
        if (!e) { e = { comm: line.t.comm, tgid: line.p ? line.p.tgid : null, total: 0 }; out.tids.set(line.t.tid, e); }
        e.total += value;
      }
    }
    return out;
  };

  function parsePT(s) {
    const i = s.indexOf('/');
    const num = i >= 0 ? s.slice(2, i) : s.slice(2);
    const comm = i >= 0 ? s.slice(i + 1) : '';
    return { num: Number(num), comm, tgid: Number(num), tid: Number(num) };
  }

  // p:123/myapp -> {tgid:123, comm:'myapp'}
  // t:456/worker  -> {tid:456, comm:'worker'}
  // (both share the parse helper; field name chosen by caller)

  // Flatten parsed p/t frames into the keys used by parseFolded output.
  // (re-export helper for clarity)
  V._parsePT = parsePT;

  // ------------------------------------------------------------------
  // Flame renderer
  // ------------------------------------------------------------------
  V.Flame = class {
    // opts: {filter:{pid,tid}, unit:'samples'|'ns'}
    constructor(canvas, opts) {
      this.canvas = canvas;
      this.opts = opts || {};
      this.data = this.opts.data || { lines: [], total: 0 };
      this.filter = this.opts.filter || { pid: null, tid: null };
      this.unit = this.opts.unit || 'samples';
      this.root = null;       // built tree (filtered)
      this.focus = null;      // current focus node
      this.breadcrumb = [];
      this.search = '';
      this.hoverNode = null;
      this.ctx = canvas.getContext('2d');
      this.dpr = global.devicePixelRatio || 1;
      this.rowH = 16;
      this._bind();
      this.rebuild();
      // 容器 hidden 时 clientWidth=0 画不出；可见后再重绘
      if (typeof ResizeObserver !== 'undefined') {
        this._ro = new ResizeObserver(() => {
          if (this.canvas.clientWidth > 0) this._render();
        });
        this._ro.observe(canvas.parentElement || canvas);
      }
    }

    setData(data, unit) {
      this.data = data || { lines: [], total: 0 };
      if (unit) this.unit = unit;
      this.search = '';
      this.breadcrumb = [];
      this.focus = null;
      this.rebuild();
    }
    setFilter(filter) { this.filter = filter || { pid: null, tid: null }; this.focus = null; this.breadcrumb = []; this.rebuild(); }
    destroy() { if (this._ro) this._ro.disconnect(); }

    setSearch(q) { this.search = q || ''; this.rebuild(); }
    reset() { this.focus = null; this.breadcrumb = []; this.rebuild(); if (this.onFocus) this.onFocus(); }

    rebuild() {
      this.root = this._buildTree();
      this.focus = this.root;
      this._render();
    }

    _buildTree() {
      const root = { name: 'root', value: 0, self: 0, children: new Map(), depth: 0, parent: null };
      const f = this.filter;
      const inPid = (l) => !f.pid || (l.p && l.p.tgid === f.pid);
      const inTid = (l) => !f.tid || (l.t && l.t.tid === f.tid);
      for (const line of this.data.lines) {
        if (!inPid(line) || !inTid(line)) continue;
        let node = root;
        root.value += line.value;
        for (let i = 0; i < line.frames.length; i++) {
          const name = line.frames[i];
          let child = node.children.get(name);
          if (!child) {
            child = { name, value: 0, self: 0, children: new Map(), depth: node.depth + 1, parent: node };
            node.children.set(name, child);
          }
          child.value += line.value;
          node = child;
        }
        node.self += line.value;
      }
      return root;
    }

    // push focus down one frame set along breadcrumb
    drill(node) {
      this.focus = node;
      this.breadcrumb.push(node);
      this._render();
      if (this.onFocus) this.onFocus();
    }
    upTo(node) {
      this.breadcrumb = [];
      let n = node;
      const chain = [];
      while (n && n.parent) { chain.unshift(n); n = n.parent; }
      // chain[0] is root child ... keep path to given node
      this.focus = node;
      // breadcrumb should be all ancestors above focus
      const anc = [];
      let cur = node.parent;
      while (cur && cur.parent) { anc.unshift(cur); cur = cur.parent; }
      this.breadcrumb = anc;
      this._render();
      if (this.onFocus) this.onFocus();
    }

    _bind() {
      const cv = this.canvas;
      cv.addEventListener('mousemove', (e) => {
        const r = cv.getBoundingClientRect();
        const x = e.clientX - r.left;
        const y = e.clientY - r.top;
        this.hoverNode = this._nodeAt(x, y);
        this._render();
        this._showHover(x, y);
      });
      cv.addEventListener('mouseleave', () => { this.hoverNode = null; this._render(); });
      cv.addEventListener('mousedown', (e) => {
        const r = cv.getBoundingClientRect();
        const x = e.clientX - r.left;
        const y = e.clientY - r.top;
        const node = this._nodeAt(x, y);
        if (node && node !== this.focus) this.drill(node);
      });
    }

    _render() {
      const cv = this.canvas;
      const w = cv.clientWidth;
      const focus = this.focus || this.root;
      const depth = this._maxDepth(focus);
      const h = (depth + 1) * this.rowH;
      this.canvas.style.height = h + 'px';
      cv.width = Math.max(1, Math.round(w * this.dpr));
      cv.height = Math.max(1, Math.round(h * this.dpr));
      const ctx = this.ctx;
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      if (!focus.value) {
        ctx.fillStyle = '#8b949e';
        ctx.font = '13px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('无调用栈数据', w / 2, 30);
        ctx.textAlign = 'left';
        this._emitStatus('0 帧');
        return;
      }

      this._drawNode(ctx, focus, 0, 0, w, focus.value);

      // search highlights
      if (this.search) {
        this._highlight(ctx, focus, 0, 0, w, focus.value);
      }
      this._emitStatus(this._statusText());
    }

    _maxDepth(node) {
      let d = node.depth;
      for (const c of node.children.values()) d = Math.max(d, this._maxDepth(c));
      return d;
    }

    _drawNode(ctx, node, x, y, w, total) {
      const pw = Math.max(0, node.value / total * w);
      const color = this._color(node);
      ctx.fillStyle = color;
      ctx.fillRect(x, y, pw, this.rowH - 1);
      if (pw >= 20) {
        ctx.fillStyle = 'rgba(255,255,255,.85)';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'left';
        ctx.save();
        ctx.beginPath();
        ctx.rect(x + 1, y + 2, pw - 2, this.rowH - 5);
        ctx.clip();
        ctx.fillText(node.name, x + 3, y + this.rowH - 5);
        ctx.restore();
      }
      // recurse (skip subtrees narrower than 0.5px)
      let cx = x;
      for (const child of node.children.values()) {
        const cw = child.value / total * w;
        if (cw < 0.5) continue;
        this._drawNode(ctx, child, cx, y + this.rowH, cw, total);
        cx += cw;
      }
    }

    _highlight(ctx, node, x, y, w, total) {
      const pw = Math.max(0, node.value / total * w);
      const hit = node.name.toLowerCase().includes(this.search.toLowerCase());
      if (!hit && pw >= 0.5) {
        // dim non-matching subtree
        ctx.fillStyle = 'rgba(13,17,23,.55)';
        ctx.fillRect(x, y, pw, this.rowH - 1);
      }
      if (hit) {
        ctx.strokeStyle = '#ff5252';
        ctx.lineWidth = 1.5;
        ctx.strokeRect(x + .5, y + .5, Math.max(pw - 1, 0), this.rowH - 2);
      }
      let cx = x;
      for (const child of node.children.values()) {
        const cw = child.value / total * w;
        if (cw < 0.5) continue;
        this._highlight(ctx, child, cx, y + this.rowH, cw, total);
        cx += cw;
      }
    }

    _nodeAt(x, y) {
      const focus = this.focus || this.root;
      if (!focus || !focus.value) return null;
      return this._hit(focus, 0, 0, this.canvas.clientWidth, focus.value, x, y);
    }
    _hit(node, x, y, w, total, px, py) {
      const pw = Math.max(0, node.value / total * w);
      if (py >= y && py < y + this.rowH && px >= x && px < x + pw) return node;
      let cx = x;
      for (const child of node.children.values()) {
        const cw = child.value / total * w;
        if (cw < 0.5) continue;
        const r = this._hit(child, cx, y + this.rowH, cw, total, px, py);
        if (r) return r;
        cx += cw;
      }
      return null;
    }

    _color(node) {
      if (node.name === 'root' || node.name.startsWith('p:') || node.name.startsWith('t:')) return '#6b7280';
      const kind = V.classifyFrame(node.name);
      let h = 0;
      for (let i = 0; i < node.name.length; i++) h = ((h * 31) + node.name.charCodeAt(i)) | 0;
      h = Math.abs(h);
      if (kind === 'user') return `hsl(${10 + h % 30} 65% 52%)`;
      return `hsl(${200 + h % 40} 45% 45%)`;
    }

    _fmtValue(v) {
      return this.unit === 'ns' ? V.fmt.bytes(v) + 'ns' : v.toLocaleString() + ' 样本';
    }

    _statusText() {
      const focus = this.focus || this.root;
      let parts = [];
      if (this.search) {
        const all = this._collectNames(focus);
        const hits = all.filter((n) => n.name.toLowerCase().includes(this.search.toLowerCase()));
        const hitVal = hits.reduce((a, n) => a + n.value, 0);
        const pct = focus.value ? (hitVal / focus.value * 100).toFixed(1) : '0';
        parts.push(`命中 ${hits.length} 帧，合计 ${pct}%`);
      }
      parts.push(`focus ${focus.value}/${this.data.total}`);
      return parts.join('  ·  ');
    }
    _collectNames(node) {
      const out = [];
      const walk = (n) => {
        out.push(n);
        for (const c of n.children.values()) walk(c);
      };
      walk(node);
      return out;
    }
    _emitStatus(text) {
      if (this.statusEl) this.statusEl.textContent = text;
    }
    _showHover(x, y) {
      const node = this.hoverNode;
      if (!this.hoverEl) return;
      if (!node) { this.hoverEl.textContent = ''; return; }
      const pctFocus = this.focus && this.focus.value ? (node.value / this.focus.value * 100).toFixed(1) : '0';
      const pctAll = this.data.total ? (node.value / this.data.total * 100).toFixed(1) : '0';
      this.hoverEl.textContent =
        `${node.name}  self=${this._fmtValue(node.self)}  total=${this._fmtValue(node.value)}` +
        `  ${pctFocus}% of focus · ${pctAll}% of all`;
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);