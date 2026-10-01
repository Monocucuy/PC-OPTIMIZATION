/* Gráficas de línea en canvas con brillo neón. Sin dependencias externas. */
(function () {
  'use strict';

  class LineChart {
    /**
     * @param {HTMLCanvasElement} canvas
     * @param {{series: {key: string, color: string}[], max?: number, format?: (v:number)=>string, points?: number}} opts
     */
    constructor(canvas, opts) {
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.series = opts.series;
      this.fixedMax = opts.max;
      this.format = opts.format || (v => v.toFixed(0));
      this.points = opts.points || 90;
      this.data = [];
      this._resize = this._resize.bind(this);
      if (window.ResizeObserver) new ResizeObserver(this._resize).observe(canvas);
      this._resize();
    }

    _resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const r = this.canvas.getBoundingClientRect();
      if (!r.width) return;
      this.w = r.width; this.h = r.height;
      this.canvas.width = r.width * dpr; this.canvas.height = r.height * dpr;
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      this.draw();
    }

    setData(rows) { this.data = rows.slice(-this.points); this.draw(); }

    draw() {
      const { ctx, w, h } = this;
      if (!w) return;
      ctx.clearRect(0, 0, w, h);
      const pad = { l: 4, r: 46, t: 8, b: 6 };
      const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
      let max = this.fixedMax;
      if (!max) {
        max = 1;
        for (const row of this.data) for (const s of this.series) max = Math.max(max, row[s.key] || 0);
        max *= 1.15;
      }
      // rejilla
      ctx.strokeStyle = 'rgba(0,255,65,0.10)';
      ctx.lineWidth = 1;
      ctx.setLineDash([2, 4]);
      ctx.font = '10px Consolas, monospace';
      ctx.fillStyle = 'rgba(90,166,111,0.9)';
      for (let i = 0; i <= 4; i++) {
        const y = pad.t + ih * (i / 4);
        ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + iw, y); ctx.stroke();
        if (i < 4) ctx.fillText(this.format(max * (1 - i / 4)), pad.l + iw + 6, y + 4);
      }
      ctx.setLineDash([]);
      if (this.data.length < 2) return;
      const step = iw / (this.points - 1);
      const x0 = pad.l + iw - step * (this.data.length - 1);
      for (const s of this.series) {
        const pts = this.data.map((row, i) => [x0 + i * step, pad.t + ih - Math.min(1, (row[s.key] || 0) / max) * ih]);
        // relleno
        const grad = ctx.createLinearGradient(0, pad.t, 0, pad.t + ih);
        grad.addColorStop(0, hexA(s.color, 0.28));
        grad.addColorStop(1, hexA(s.color, 0));
        ctx.beginPath();
        ctx.moveTo(pts[0][0], pad.t + ih);
        for (const [x, y] of pts) ctx.lineTo(x, y);
        ctx.lineTo(pts[pts.length - 1][0], pad.t + ih);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();
        // línea con brillo
        ctx.beginPath();
        pts.forEach(([x, y], i) => (i ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
        ctx.strokeStyle = s.color;
        ctx.lineWidth = 1.6;
        ctx.shadowColor = s.color;
        ctx.shadowBlur = 8;
        ctx.stroke();
        ctx.shadowBlur = 0;
        // punto final
        const [lx, ly] = pts[pts.length - 1];
        ctx.fillStyle = '#eafff0';
        ctx.beginPath(); ctx.arc(lx, ly, 2.4, 0, Math.PI * 2); ctx.fill();
      }
    }
  }

  function hexA(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
  }

  window.LineChart = LineChart;
})();
