/* eTrace-Diag viz — TChart: canvas time-series line chart component. */
(function (global) {
  'use strict';
  const V = global.V = global.V || {};

  V.PALETTE = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff',
               '#39c5cf', '#ff9e64', '#e3b341', '#76e3ea', '#f778ba'];
  // 所有存活图表的注册表（destroy 时移除）；用于「事件标记」等全局开关的统一重绘
  V.allCharts = new Set();

  // LinkGroup: shared viewport {x0,x1, subs:[chart], busy}
  V.LinkGroup = class {
    constructor() { this.x0 = null; this.x1 = null; this.subs = []; this.busy = false; }
    set(x0, x1) {
      this.x0 = x0; this.x1 = x1;
      if (this.busy) return;
      this.busy = true;
      for (const c of this.subs) c.setView(x0, x1, true);
      this.busy = false;
    }
    reset() {
      this.x0 = null; this.x1 = null;
      if (this.busy) return;
      this.busy = true;
      for (const c of this.subs) c.resetView(true);
      this.busy = false;
    }
    add(c) {
      if (this.subs.includes(c)) return;
      this.subs.push(c);
      // 新图加入时回放当前组视口，避免后加入的图与组视口脱节
      if (this.x0 != null && this.x1 != null) c.setView(this.x0, this.x1, true);
    }
    remove(c) { this.subs = this.subs.filter((s) => s !== c); }
  };

  V.TChart = class {
    // opts: {leftScale, rightScale?, events?, bands?, link?, height?, wall?}
    constructor(canvas, opts) {
      this.canvas = canvas;
      this.opts = opts || {};
      this.series = new Map();   // id -> {label,color,x,y,scale,kind,visible}
      this.order = [];
      this.view = { x0: null, x1: null };  // null => full data range
      this.link = this.opts.link || null;
      this.height = this.opts.height || 220;
      this.dpr = (global.devicePixelRatio || 1);
      this.hover = null;
      this.raf = 0;
      this.dirty = true;

      if (this.link) this.link.add(this);

      const wrap = document.createElement('div');
      wrap.className = 'tchart';
      wrap.style.position = 'relative';
      this.legend = document.createElement('div');
      this.legend.className = 'legend';
      this.movedPx = 0;   // mousedown 起累计位移；click 用它区分「点击」与「拖拽平移」
      // height 指绘图区高度；wrap 高度自适应（legend + 图），避免溢出被 overflow:hidden 裁掉
      this.tooltip = document.createElement('div');
      this.tooltip.className = 'tt';
      this.tooltip.style.display = 'none';
      canvas.className = 'plot';
      canvas.style.height = this.height + 'px';
      // if the caller already placed the canvas in the DOM, swap in the wrapper
      const host = canvas.parentNode;
      if (host) {
        host.replaceChild(wrap, canvas);
      }
      if (this.opts.legend !== false) wrap.appendChild(this.legend);
      wrap.appendChild(canvas);
      wrap.appendChild(this.tooltip);
      this.wrap = wrap;
      this.ctx = canvas.getContext('2d');

      this._bind();
      if (typeof ResizeObserver !== 'undefined') {
        this._ro = new ResizeObserver(() => this.requestRedraw());
        this._ro.observe(wrap);
      }
      V.allCharts.add(this);
    }

    addSeries({ id, label, color, x, y, scale, kind, unit, scaleName }) {
      const sc = scale || 'left';
      const c = color || V.PALETTE[this.order.length % V.PALETTE.length];
      this.series.set(id, { id, label, color: c, x: Float64Array.from(x), y: Float64Array.from(y),
                            scale: sc, kind: kind || 'line', visible: true,
                            unit: unit || null, scaleName: scaleName || null });
      this.order.push(id);
      this._rebuildLegend();
      this.requestRedraw();
    }
    removeSeries(id) {
      this.series.delete(id);
      this.order = this.order.filter((s) => s !== id);
      this._rebuildLegend();
      this.requestRedraw();
    }
    setVisible(id, on) {
      const s = this.series.get(id);
      if (!s) return;
      s.visible = !!on;
      this._rebuildLegend();
      this.requestRedraw();
    }
    setKind(id, kind) { const s = this.series.get(id); if (s) { s.kind = kind; this.requestRedraw(); } }

    // ------------------------------------------------------------------
    // viewport
    // ------------------------------------------------------------------
    _fullRange() {
      let lo = Infinity, hi = -Infinity;
      for (const id of this.order) {
        const s = this.series.get(id);
        if (!s || !s.visible || s.x.length === 0) continue;
        if (s.x[0] < lo) lo = s.x[0];
        if (s.x[s.x.length - 1] > hi) hi = s.x[s.x.length - 1];
      }
      if (!isFinite(lo)) { lo = 0; hi = 1; }
      if (hi <= lo) hi = lo + 1;
      return [lo, hi];
    }
    setView(x0, x1, fromLink) {
      this.view.x0 = x0; this.view.x1 = x1;
      this.requestRedraw();
    }
    resetView(fromLink) { this.view.x0 = this.view.x1 = null; this.requestRedraw(); }
    destroy() {
      if (this.link) this.link.remove(this);
      if (this._ro) this._ro.disconnect();
      if (this._onWinUp) window.removeEventListener('mouseup', this._onWinUp);
      this.wrap.remove();
      V.allCharts.delete(this);
    }

    // ------------------------------------------------------------------
    // interaction
    // ------------------------------------------------------------------
    _bind() {
      const cv = this.canvas;
      let dragging = false, dragX = 0, startView = null;
      const minW = 0.5, zoom = 1.25;

      cv.addEventListener('mousedown', (e) => {
        dragging = true; dragX = e.offsetX;
        this._downX = e.clientX; this._lastX = e.clientX; this.movedPx = 0;
        const [lo, hi] = this._viewRange();
        startView = [lo, hi];
      });
      cv.addEventListener('mousemove', (e) => {
        if (dragging) {
          this._lastX = e.clientX;
          const dx = e.offsetX - dragX;
          const [lo, hi] = this._viewRange();
          const span = hi - lo;
          const shift = dx / (this._geom ? this._geom.iw : cv.clientWidth) * span;
          let nlo = startView[0] - shift, nhi = startView[1] - shift;
          const [flo, fhi] = this._fullRange();
          if (nlo < flo) { nhi += flo - nlo; nlo = flo; }
          if (nhi > fhi) { nlo -= nhi - fhi; nhi = fhi; }
          this._setUserView(nlo, nhi);
        } else {
          this.hover = e.offsetX;
          this._drawTooltip(e);
          this.requestRedraw();
        }
      });
      cv.addEventListener('mouseleave', () => { this.hover = null; this.tooltip.style.display = 'none'; this.requestRedraw(); });
      const endDrag = () => {
        if (dragging) { dragging = false; this.movedPx = Math.abs(this._lastX - this._downX); }
      };
      this._onWinUp = endDrag;
      cv.addEventListener('mouseup', endDrag);
      window.addEventListener('mouseup', endDrag);   // 松手在 canvas 外也能结束拖拽，避免粘滞
      cv.addEventListener('wheel', (e) => {
        e.preventDefault();
        const [lo, hi] = this._viewRange();
        const w = cv.clientWidth;
        const g = this._geom || { padL: 0, iw: w };
        const fx = Math.min(1, Math.max(0, (e.offsetX - g.padL) / g.iw));
        const c = lo + (hi - lo) * fx;
        const k = e.deltaY < 0 ? 1 / zoom : zoom;
        let nlo = c - (c - lo) * k, nhi = c + (hi - c) * k;
        if (nhi - nlo < minW) { const mid = (nlo + nhi) / 2; nlo = mid - minW / 2; nhi = mid + minW / 2; }
        const [flo, fhi] = this._fullRange();
        if (nlo < flo) { nlo = flo; nhi = Math.min(fhi, nlo + Math.max(minW, (hi - lo) * k)); }
        if (nhi > fhi) { nhi = fhi; nlo = Math.max(flo, nhi - Math.max(minW, (hi - lo) * k)); }
        this._setUserView(nlo, nhi);
      }, { passive: false });
      cv.addEventListener('dblclick', () => {
        if (this.link && global.document.getElementById('chkLink')?.checked) this.link.reset();
        else this.resetView();
      });

      // touch: single-finger pan, pinch zoom
      let touches = new Map();
      cv.addEventListener('touchstart', (e) => { for (const t of e.changedTouches) touches.set(t.identifier, t.clientX); },
        { passive: true });
      cv.addEventListener('touchmove', (e) => {
        e.preventDefault();
        if (e.touches.length === 1) {
          const t = e.touches[0];
          const px = touches.get(t.identifier);
          if (px != null) {
            const [lo, hi] = this._viewRange();
            const span = hi - lo;
            const shift = (t.clientX - px) / (this._geom ? this._geom.iw : cv.clientWidth) * span;
            let nlo = lo - shift, nhi = hi - shift;
            const [flo, fhi] = this._fullRange();
            if (nlo < flo) { nhi += flo - nlo; nlo = flo; }
            if (nhi > fhi) { nlo -= nhi - fhi; nhi = fhi; }
            this._setUserView(nlo, nhi);
          }
          touches.set(t.identifier, t.clientX);
        } else if (e.touches.length === 2) {
          const [a, b] = [e.touches[0], e.touches[1]];
          const pa = touches.get(a.identifier), pb = touches.get(b.identifier);
          if (pa != null && pb != null) {
            const pd = Math.abs(pa - pb), cd = Math.abs(a.clientX - b.clientX);
            if (pd > 0 && cd > 0) {
              const k = pd / cd;
              const [lo, hi] = this._viewRange();
              const mid = (lo + hi) / 2;
              let nlo = mid - (mid - lo) * k, nhi = mid + (hi - mid) * k;
              if (nhi - nlo < minW) { const m = (nlo + nhi) / 2; nlo = m - minW / 2; nhi = m + minW / 2; }
              // 钳制到数据范围（避免超界空窗）
              const [flo, fhi] = this._fullRange();
              if (nlo < flo) { nlo = flo; nhi = Math.min(fhi, flo + Math.max(minW, (hi - lo) * k)); }
              if (nhi > fhi) { nhi = fhi; nlo = Math.max(flo, fhi - Math.max(minW, (hi - lo) * k)); }
              this._setUserView(nlo, nhi);
            }
          }
          touches.set(a.identifier, a.clientX); touches.set(b.identifier, b.clientX);
        }
      }, { passive: false });
      cv.addEventListener('touchend', (e) => { for (const t of e.changedTouches) touches.delete(t.identifier); },
        { passive: true });
    }

    _viewRange() {
      const [flo, fhi] = this._fullRange();
      let lo = this.view.x0, hi = this.view.x1;
      if (lo == null) lo = flo;
      if (hi == null) hi = fhi;
      // 联动缩放会收到别的图的时间窗：钳制到本图数据范围，避免整图空白
      const span = Math.max(hi - lo, 0.5);
      if (lo < flo) { lo = flo; hi = Math.min(fhi, flo + span); }
      if (hi > fhi) { hi = fhi; lo = Math.max(flo, fhi - span); }
      return [lo, hi];
    }
    _setUserView(nlo, nhi) {
      this.view.x0 = nlo; this.view.x1 = nhi;
      if (this.link && global.document.getElementById('chkLink')?.checked) this.link.set(nlo, nhi);
      this.requestRedraw();
    }

    // ------------------------------------------------------------------
    // legend
    // ------------------------------------------------------------------
    _rebuildLegend() {
      this.legend.textContent = '';
            for (const id of this.order) {
        const s = this.series.get(id);
        if (!s) continue;
        const chip = V.el('span', { class: 'legend-chip' + (s.visible ? '' : ' off') },
          [V.el('span', { class: 'chip-color', style: 'background:' + s.color }), s.label]);
        chip.addEventListener('click', () => this.setVisible(id, !s.visible));
        this.legend.appendChild(chip);
      }
    }

    // ------------------------------------------------------------------
    // drawing
    // ------------------------------------------------------------------
    requestRedraw() {
      if (this.raf) return;
      this.raf = requestAnimationFrame(() => { this.raf = 0; this.draw(); });
    }

    draw() {
      const cv = this.canvas;
      const w = cv.clientWidth, h = this.height;
      if (!w) return;
      cv.width = Math.max(1, Math.round(w * this.dpr));
      cv.height = Math.max(1, Math.round(h * this.dpr));
      const ctx = this.ctx;
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const [lo, hi] = this._viewRange();
      const span = hi - lo;

      // visible series
      const vis = this.order.map((id) => this.series.get(id)).filter((s) => s && s.visible && s.x.length);
      const hasRight = vis.some((s) => s.scale === 'right');

      // ---- y ranges：锁轴由该侧可见序列的 scaleName 决定 —— 同侧量纲唯一时应用其
      // lock0/lock100；混合量纲自动缩放（不再按面板锁死 0-100） ----
      const singleScaleName = (side) => {
        let name = null, mixed = false;
        for (const s of vis) {
          if (s.scale !== side || !s.scaleName) continue;
          if (name == null) name = s.scaleName;
          else if (name !== s.scaleName) mixed = true;
        }
        return mixed ? null : name;
      };
      const range = (side) => {
        let mn = Infinity, mx = -Infinity;
        for (const s of vis) {
          if (s.scale !== side) continue;
          for (let i = 0; i < s.y.length; i++) {
            const v = s.y[i];
            if (!isFinite(v)) continue;
            if (v < mn) mn = v; if (v > mx) mx = v;
          }
        }
        if (!isFinite(mn)) return [[0, 1], null];
        const scName = singleScaleName(side);
        const sc = scName ? (V.SCALES[scName] || {}) : {};
        if (sc.lock0 && mn > 0) mn = 0;
        if (sc.lock100 && mx < 100) mx = 100;
        const pad = (mx - mn) * 0.05 || 1;
        return [[mn - pad, mx + pad], scName];
      };
      const [yL, scNameL] = range('left');
      const [yR, scNameR] = hasRight ? range('right') : [[0, 1], null];

      // ---- 图区留白：坐标标签有专属区域，不再与数据/填充互相遮挡 ----
      const padT = 16, padB = 16;
      ctx.font = '10px sans-serif';
      const axisL = V.ticks(yL[0], yL[1], 5);
      const axisR = hasRight && yR ? V.ticks(yR[0], yR[1], 5) : null;
      const digL = V.tickDigits(axisL);
      const digR = axisR ? V.tickDigits(axisR) : 0;
      let padL = 8;
      for (const t of axisL) padL = Math.max(padL, ctx.measureText(V.fmt.num(t, digL)).width + 8);
      let padR = 8;
      if (axisR) {
        padR = 8;
        for (const t of axisR) padR = Math.max(padR, ctx.measureText(V.fmt.num(t, digR)).width + 8);
      }
      padL = Math.ceil(padL); padR = Math.ceil(padR);
      const iw = Math.max(1, w - padL - padR);   // 绘图区宽
      const ih = Math.max(1, h - padT - padB);   // 绘图区高
      this._geom = { padL, padR, padT, padB, iw, ih };

      const px = (x) => padL + (x - lo) / span * iw;
      const yPix = (v, side) => {
        const [mn, mx] = side === 'right' ? yR : yL;
        return padT + ih - (v - mn) / (mx - mn) * ih;
      };

      // ---- grid + axis ----
      ctx.strokeStyle = 'rgba(48,54,61,.5)';
      ctx.fillStyle = '#8b949e';
      ctx.lineWidth = 1;
      ctx.textAlign = 'right';
      for (const t of axisL) {
        const y = yPix(t, 'left');
        ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
        ctx.fillText(V.fmt.num(t, digL), padL - 4, y + 3);
      }
      if (axisR) {
        ctx.textAlign = 'left';
        for (const t of axisR) {
          const y = yPix(t, 'right');
          ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y);
          ctx.strokeStyle = 'rgba(48,54,61,.2)'; ctx.stroke();
          ctx.strokeStyle = 'rgba(48,54,61,.5)';
          ctx.fillText(V.fmt.num(t, digR), w - padR + 4, y + 3);
        }
      }
      // 单量纲时在轴顶端标注单位
      const unitL = scNameL && V.SCALES[scNameL] ? V.SCALES[scNameL].unit : '';
      const unitR = scNameR && V.SCALES[scNameR] ? V.SCALES[scNameR].unit : '';
      if (unitL) { ctx.textAlign = 'left'; ctx.fillText(unitL, padL, 9); }
      if (unitR) { ctx.textAlign = 'right'; ctx.fillText(unitR, w - padR, 9); }
      // x axis time ticks（标签在底部留白区，居中刻度，两端夹紧不越界）
      const xTicks = V.xticks(lo, hi, iw);
      ctx.fillStyle = '#8b949e';
      ctx.textAlign = 'center';
      let prevRight = -Infinity;   // 已画标签的右缘，防止碰撞
      for (const t of xTicks) {
        const x = px(t);
        ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + ih);
        ctx.strokeStyle = 'rgba(48,54,61,.25)'; ctx.stroke();
        const label = this._wallLabel(t);
        const half = ctx.measureText(label).width / 2;
        const lx = Math.min(Math.max(x, padL + half), w - padR - half);
        const lft = lx - half;
        if (lft < prevRight + 6) continue;   // 与前标签过近则丢弃（网格线仍在）
        prevRight = lx + half;
        ctx.fillText(label, lx, h - 4);
      }
      ctx.textAlign = 'left';
      // ---- event / band overlays ----
      const ev = this.opts.events, bands = this.opts.bands;
      if (ev && global.document.getElementById('chkEvents')?.checked) {
        let count = 0;
        for (const e of ev) {
          if (e.x < lo || e.x > hi) continue;
          count++;
        }
        if (count > 30) {
          ctx.fillStyle = '#f85149';
          ctx.fillText(count + ' 事件', w - padR - 70, padT + 1);
        } else {
          for (const e of ev) {
            if (e.x < lo || e.x > hi) continue;
            const x = px(e.x);
            ctx.strokeStyle = '#f85149';
            ctx.setLineDash([3, 3]);
            ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + ih); ctx.stroke();
            ctx.setLineDash([]);
          }
        }
      }
      if (bands) {
        for (const b of bands) {
          const x0 = Math.max(px(b.x0), padL), x1 = Math.min(px(b.x1), w - padR);
          if (x1 < padL || x0 > w - padR) continue;
          ctx.fillStyle = 'rgba(248,81,73,.07)';
          ctx.fillRect(x0, padT, x1 - x0, ih);
          ctx.strokeStyle = 'rgba(248,81,73,.5)';
          ctx.strokeRect(x0, padT, x1 - x0, ih);
          ctx.fillStyle = '#f85149';
          ctx.fillText(b.label, x0 + 3, padT + 11);
        }
      }

      // ---- series ----
      let anyPointInWindow = false;
      // 数据裁剪到绘图区内，不越入坐标轴留白
      ctx.save();
      ctx.beginPath(); ctx.rect(padL, 0, iw, padT + ih); ctx.clip();
      for (const id of this.order) {
        const s = this.series.get(id);
        if (!s || !s.visible || s.x.length === 0) continue;
        // 窗口内是否有数据点（x 单调，端点判断即可）
        if (s.x[s.x.length - 1] >= lo && s.x[0] <= hi) anyPointInWindow = true;
        this._drawSeries(ctx, s, px, yPix, iw, ih, lo, hi);
      }
      ctx.restore();

      // ---- crosshair ----
      if (this.hover != null && this.hover >= padL && this.hover <= w - padR) {
        const x = this.hover;
        ctx.strokeStyle = 'rgba(139,148,158,.4)';
        ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + ih); ctx.stroke();
      }

      // empty state
      if (!vis.length || !anyPointInWindow) {
        ctx.fillStyle = '#8b949e';
        ctx.font = '13px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('所选窗口无数据', padL + iw / 2, padT + ih / 2);
        ctx.textAlign = 'left';
      }
    }

    _wallLabel(x) {
      if (this.opts.wall && this.opts.wall.anchor) {
        // x 已是会话相对秒（ts_ns - t0），直接加在锚点上 —— 不能再叠加 t0（净 otherwise 会多算一份 uptime）
        const d = new Date(this.opts.wall.anchor.getTime() + x * 1000);
        return V.fmt.hms(d);
      }
      return V.fmt.num(x, 1) + 's';
    }

    _drawSeries(ctx, s, px, yPix, w, h, lo, hi) {
      // decimate to pixels: bucket by x-pixel; keep min/max for spikes
      const span = hi - lo;
      const n = s.x.length;
      const buckets = new Map();
      for (let i = 0; i < n; i++) {
        const x = s.x[i], y = s.y[i];
        if (x < lo || x > hi || !isFinite(y)) continue;
        const g = this._geom;
        const bx = Math.max(g.padL, Math.min(g.padL + w - 1, Math.floor(px(x))));
                let b = buckets.get(bx);
        if (!b) { b = { mn: y, mx: y, n: 1, last: [x, y] }; buckets.set(bx, b); }
        else {
          if (y < b.mn) b.mn = y;
          if (y > b.mx) b.mx = y;
          b.n++;
          b.last = [x, y];
        }
      }
      if (!buckets.size) return;
      const bx = [...buckets.keys()].sort((a, b) => a - b);

      ctx.strokeStyle = s.color;
      ctx.lineWidth = 1.4;
      ctx.fillStyle = s.color;
      ctx.beginPath();
      if (s.kind === 'area') {
        ctx.moveTo(bx[0], yPix(buckets.get(bx[0]).mn, s.scale));
        for (const b of bx) {
          const e = buckets.get(b);
          if (e.n > 2) { ctx.lineTo(b + .5, yPix(e.mn, s.scale)); ctx.lineTo(b + .5, yPix(e.mx, s.scale)); }
          else ctx.lineTo(b + .5, yPix(e.last[1], s.scale));
        }
        ctx.stroke();
        // fill
        ctx.globalAlpha = .25;
        ctx.beginPath();
        ctx.moveTo(bx[0], yPix(buckets.get(bx[0]).mn, s.scale));
        for (const b of bx) {
          const e = buckets.get(b);
          if (e.n > 2) ctx.lineTo(b + .5, yPix(e.mn, s.scale));
          else ctx.lineTo(b + .5, yPix(e.last[1], s.scale));
        }
        ctx.lineTo(bx[bx.length - 1] + .5, this._geom.padT + h);
        ctx.lineTo(bx[0], this._geom.padT + h);
        ctx.closePath();
        ctx.fill();
        ctx.globalAlpha = 1;
        return;
      }
      if (s.kind === 'step') {
        let prevY = null;
        for (const b of bx) {
          const e = buckets.get(b);
          const y = e.n > 2 ? e.mn : e.last[1];
          const yy = yPix(y, s.scale);
          if (prevY != null) ctx.lineTo(b + .5, prevY);
          ctx.lineTo(b + .5, yy);
          prevY = yy;
        }
        ctx.stroke();
        return;
      }
      // line
      let anyPoint = false;
      for (const b of bx) {
        const e = buckets.get(b);
        if (e.n > 2) {
          ctx.lineTo(b + .5, yPix(e.mn, s.scale));
          ctx.lineTo(b + .5, yPix(e.mx, s.scale));
        } else {
          ctx.lineTo(b + .5, yPix(e.last[1], s.scale));
          anyPoint = true;
        }
      }
      ctx.stroke();
      if (bx.length === 1) {
        // 窗口内单点：画圆点避免视觉上“图被清空”
        const b = bx[0];
        const e = buckets.get(b);
        ctx.beginPath();
        ctx.arc(b + .5, yPix(e.last[1], s.scale), 2, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    _drawTooltip(e) {
      const [lo, hi] = this._viewRange();
      const w = this.canvas.clientWidth;
      const x = e.offsetX;
      const g = this._geom || { padL: 0, iw: w };
      const fx = (x - g.padL) / g.iw;
      if (fx < 0 || fx > 1) { this.tooltip.style.display = 'none'; return; }
      const rel = lo + (hi - lo) * fx;
      const vis = this.order.map((id) => this.series.get(id)).filter((s) => s && s.visible && s.x.length);
      if (!vis.length) { this.tooltip.style.display = 'none'; return; }

      // nearest point per series (binary search since x monotonic)
      const lines = [];
      for (const s of vis) {
        const idx = this._nearest(s.x, rel);
        const v = idx >= 0 ? s.y[idx] : null;
        const sx = idx >= 0 ? s.x[idx] : null;
        lines.push({ s, v, sx });
      }
      const wall = this._wallLabel(rel);
      let html = `<div class="tt-line">${wall} · ${V.fmt.rel(rel)}</div>`;
      for (const l of lines) {
        const val = l.v == null || !isFinite(l.v) ? '—' : V.fmt.num(l.v, 2) + (l.s.unit ? ' ' + l.s.unit : '');
        html += `<div class="tt-line"><span style="color:${l.s.color}">●</span> ${l.s.label}: ${val}</div>`;
      }
      this.tooltip.innerHTML = html;
      this.tooltip.style.display = 'block';
      const tw = this.tooltip.offsetWidth;
      const tx = x + 12 + tw > w ? x - tw - 12 : x + 12;
      this.tooltip.style.left = Math.max(0, tx) + 'px';
      this.tooltip.style.top = '8px';
    }

    _nearest(arr, rel) {
      if (!arr.length) return -1;
      let lo = 0, hi = arr.length - 1;
      if (rel <= arr[0]) return 0;
      if (rel >= arr[hi]) return hi;
      while (hi - lo > 1) {
        const mid = (lo + hi) >> 1;
        if (arr[mid] <= rel) lo = mid; else hi = mid;
      }
      return (rel - arr[lo] <= arr[hi] - rel) ? lo : hi;
    }
  };

  // nice ticks (1/2/2.5/5 × 10^k)
  // 刻度小数位：步长 <1 时给到可看分差的小数位（如 step=0.25 → 2 位）
  V.tickDigits = function (ticks) {
    // 返回让相邻刻度 label 互不相同的 最少 小数位（解决 step=0.25 → "0/0/1" 重复标签）
    for (let d = 0; d <= 4; d++) {
      const seen = new Set();
      let ok = true;
      for (const t of ticks) {
        const s = t.toFixed(d);
        if (seen.has(s)) { ok = false; break; }
        seen.add(s);
      }
      if (ok) return d;
    }
    return 4;
  };

  V.ticks = function (mn, mx, count) {
    const span = mx - mn;
    if (span <= 0) return [mn];
    const raw = span / count;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    let step;
    if (norm < 1.5) step = 1; else if (norm < 3) step = 2; else if (norm < 4) step = 2.5;
    else if (norm < 7) step = 5; else step = 10;
    step *= mag;
    const out = [];
    for (let v = Math.ceil(mn / step) * step; v <= mx + step / 2; v += step) out.push(+v.toFixed(10));
    return out;
  };
  V.xticks = function (lo, hi, w) {
    const span = hi - lo;
    const count = Math.max(2, Math.floor(w / 90));
    const raw = span / count;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    let step;
    if (norm < 1.5) step = 1; else if (norm < 3) step = 2; else if (norm < 4) step = 2.5;
    else if (norm < 7) step = 5; else step = 10;
    step *= mag;
    const out = [];
    for (let v = Math.ceil(lo / step) * step; v <= hi + step / 2; v += step) out.push(+v.toFixed(10));
    return out;
  };
})(typeof window !== 'undefined' ? window : globalThis);