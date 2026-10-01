/* Núcleo del frontend: API, estado, utilidades y componentes compartidos. */
(function () {
  'use strict';

  const MS = window.MS = {
    token: document.querySelector('meta[name="ms-token"]').content,
    reduceMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    state: { system: null, config: null, results: {}, vt: {}, live: null, history: [] },
    running: {},
    _listeners: {},
  };

  // ------------------------------------------------------------ eventos
  MS.on = (evt, fn) => { (MS._listeners[evt] = MS._listeners[evt] || []).push(fn); };
  MS.emit = (evt, data) => (MS._listeners[evt] || []).forEach(fn => { try { fn(data); } catch (e) { console.error(e); } });

  // ------------------------------------------------------------ API
  MS.api = async function (path, opts = {}) {
    const res = await fetch(path, {
      method: opts.method || 'GET',
      headers: { 'X-MS-Token': MS.token, 'Content-Type': 'application/json' },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch (_) { /* sin cuerpo */ }
    if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
    return data;
  };

  // ------------------------------------------------------------ utilidades
  MS.$ = (sel, root = document) => root.querySelector(sel);
  MS.$$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  MS.sleep = ms => new Promise(r => setTimeout(r, ms));

  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  MS.esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ESC[c]);

  MS.fmtBytes = function (n, digits = 1) {
    if (n == null || isNaN(n)) return '--';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0; let v = Math.abs(n);
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(v >= 100 ? 0 : digits)) + ' ' + units[i];
  };
  MS.fmtRate = n => MS.fmtBytes(n) + '/s';
  MS.fmtNum = n => (n == null ? '--' : Number(n).toLocaleString('es-CO'));
  MS.fmtPct = (n, d = 0) => (n == null || isNaN(n) ? '--' : Number(n).toFixed(d) + '%');
  MS.fmtAgo = function (ts) {
    if (!ts) return 'nunca';
    const days = Math.floor((Date.now() / 1000 - ts) / 86400);
    if (days <= 0) return 'hoy';
    if (days === 1) return 'ayer';
    if (days < 60) return `hace ${days} días`;
    if (days < 730) return `hace ${Math.round(days / 30)} meses`;
    return `hace ${(days / 365).toFixed(1)} años`;
  };
  MS.fmtDays = function (d) {
    if (d == null) return '--';
    if (d < 60) return `${d} días`;
    if (d < 730) return `${Math.round(d / 30)} meses`;
    return `${(d / 365).toFixed(1)} años`;
  };
  MS.fmtDuration = function (s) {
    s = Math.max(0, Math.round(s));
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return (h ? h + 'h ' : '') + (h || m ? m + 'm ' : '') + sec + 's';
  };
  MS.fmtDate = ts => (ts ? new Date(ts * 1000).toLocaleString('es-CO', { dateStyle: 'medium', timeStyle: 'short' }) : '--');

  MS.html = function (str) {
    const t = document.createElement('template');
    t.innerHTML = str.trim();
    return t.content;
  };

  MS.toast = function (msg, type = '') {
    const box = MS.$('#toasts');
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 320); }, type === 'err' ? 6500 : 4000);
  };

  /** Anima un número desde 0 hasta su valor final. */
  MS.countUp = function (el, to, fmt = v => Math.round(v), ms = 1100) {
    if (MS.reduceMotion || !isFinite(to)) { el.textContent = fmt(to); return; }
    const start = performance.now();
    const step = now => {
      const k = Math.min(1, (now - start) / ms);
      const e = 1 - Math.pow(1 - k, 3);
      el.textContent = fmt(to * e);
      if (k < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  /** Efecto de texto que se 'descifra' desde caracteres aleatorios. */
  const SCR = 'ｱｲｳｴｵｶｷ01234567890#$%&*+=<>/';
  MS.scramble = function (el) {
    if (MS.reduceMotion) return;
    const final = el.dataset.final || el.textContent;
    el.dataset.final = final;
    let frame = 0;
    const total = 18;
    clearInterval(el._scr);
    el._scr = setInterval(() => {
      frame++;
      const reveal = Math.floor((frame / total) * final.length);
      el.textContent = final.split('').map((c, i) => (i < reveal || c === ' ' ? c : SCR[(Math.random() * SCR.length) | 0])).join('');
      if (frame >= total) { clearInterval(el._scr); el.textContent = final; }
    }, 28);
  };

  MS.meter = (pct, cls = '') => `<div class="meter ${cls}"><i style="width:${Math.max(0, Math.min(100, pct)).toFixed(1)}%"></i></div>`;
  MS.badge = (text, cls) => `<span class="badge ${MS.esc(cls || text)}">${MS.esc(text)}</span>`;
  MS.openBtn = path => (path ? `<button class="btn btn-xs" data-open="${MS.esc(path)}" title="Abrir ubicación en el Explorador">[ ABRIR ]</button>` : '');

  // Botones [ ABRIR ]: delegación global
  document.addEventListener('click', async ev => {
    const btn = ev.target.closest('[data-open]');
    if (!btn) return;
    ev.preventDefault();
    try { await MS.api('/api/open', { method: 'POST', body: { path: btn.dataset.open } }); }
    catch (e) { MS.toast(e.message, 'err'); }
  });

  /** Tabla ordenable genérica. columns: [{key, label, cls, render(row), sort(row)}] */
  MS.table = function (container, rows, columns, opts = {}) {
    const state = container._tbl || (container._tbl = { key: opts.sortKey || null, dir: opts.sortDir || -1 });
    const render = () => {
      let data = rows.slice();
      const col = columns.find(c => c.key === state.key);
      if (col) {
        const get = col.sort || (r => r[col.key]);
        data.sort((a, b) => {
          const x = get(a), y = get(b);
          if (x == null) return 1; if (y == null) return -1;
          return (x > y ? 1 : x < y ? -1 : 0) * state.dir;
        });
      }
      const limit = opts.limit || 400;
      const head = columns.map(c => `<th class="${c.sortable === false ? '' : 'sortable'} ${state.key === c.key ? 'sorted' : ''} ${c.cls || ''}" data-k="${c.key}">${MS.esc(c.label)}${state.key === c.key ? (state.dir > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('');
      const body = data.slice(0, limit).map((r, i) => `<tr class="${opts.rowClass ? opts.rowClass(r) : ''}" style="animation-delay:${Math.min(i, 30) * 18}ms">${columns.map(c => `<td class="${c.cls || ''}">${c.render ? c.render(r) : MS.esc(r[c.key])}</td>`).join('')}</tr>`).join('');
      const more = data.length > limit ? `<p class="muted small">… y ${data.length - limit} más.</p>` : '';
      container.innerHTML = `<div class="tbl-wrap"><table class="tbl"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${more}`;
      MS.$$('th.sortable', container).forEach(th => th.addEventListener('click', () => {
        if (state.key === th.dataset.k) state.dir *= -1; else { state.key = th.dataset.k; state.dir = -1; }
        render();
      }));
    };
    render();
  };

  // ------------------------------------------------------------ terminal
  class Terminal {
    constructor(el, max = 400) { this.el = el; this.max = max; this.queue = []; this.busy = false; }
    static classify(line) {
      if (/ERROR|\[!!\]|malicioso|MALICIOSO|¡Defender encontró/.test(line)) return 'err';
      if (/sin permiso|requiere admin|no se pudo|No se pudo|SOSPECHOSO|\[~~\]|Cancelado/i.test(line)) return 'warn';
      if (line.startsWith('>')) return 'cmd';
      return 'dim';
    }
    write(text, tag) {
      this.queue.push({ text, tag });
      if (!this.busy) this._drain();
    }
    async _drain() {
      this.busy = true;
      while (this.queue.length) {
        const { text, tag } = this.queue.shift();
        const line = document.createElement('div');
        line.className = 'tl ' + Terminal.classify(text);
        if (tag) { const t = document.createElement('span'); t.className = 'tag'; t.textContent = `[${tag}] `; line.appendChild(t); }
        const span = document.createElement('span');
        line.appendChild(span);
        this.el.appendChild(line);
        if (MS.reduceMotion || this.queue.length > 6 || text.length > 160) {
          span.textContent = text;
        } else {
          for (let i = 0; i < text.length; i += 3) {
            span.textContent = text.slice(0, i + 3);
            this.el.scrollTop = this.el.scrollHeight;
            await MS.sleep(6);
          }
        }
        while (this.el.childElementCount > this.max) this.el.firstElementChild.remove();
        this.el.scrollTop = this.el.scrollHeight;
      }
      this.busy = false;
    }
    clear() { this.queue = []; this.el.innerHTML = ''; }
  }
  MS.Terminal = Terminal;

  // ------------------------------------------------------------ trabajos
  const LABELS = {
    junk: 'BASURA', large: 'GRANDES', duplicates: 'DUPLICADOS', programs: 'PROGRAMAS', processes: 'PROCESOS',
    persistence: 'ARRANQUE', defender_status: 'DEFENDER', defender_scan: 'DEFENDER-SCAN', virustotal: 'VIRUSTOTAL',
    benchmark: 'BENCHMARK',
  };
  MS.jobLabel = k => LABELS[k] || k.toUpperCase();

  function buildBox(box) {
    box.innerHTML = `
      <div class="jb-head"><span class="jb-msg">iniciando…</span><span class="jb-time"></span><span class="jb-pct"></span>
      <button class="btn btn-xs btn-danger jb-cancel">[ ABORTAR ]</button></div>
      <div class="bar indet"><div class="bar-fill"></div></div>
      <div class="terminal"></div>`;
    box._term = new Terminal(MS.$('.terminal', box), 200);
    return box;
  }

  /**
   * Lanza un trabajo en el backend y sigue su progreso.
   * @returns {Promise<object|null>} el resultado, o null si falló o se canceló
   */
  MS.runJob = async function (kind, params = {}, opts = {}) {
    if (MS.running[kind]) { MS.toast('Ese análisis ya está en curso.'); return null; }
    const boxes = [MS.$(`[data-box="${kind}"]`), opts.box].filter(Boolean);
    let id;
    try {
      ({ id } = await MS.api('/api/jobs', { method: 'POST', body: { kind, params } }));
    } catch (e) {
      MS.toast(e.message, 'err');
      return null;
    }
    MS.running[kind] = id;
    boxes.forEach(b => { buildBox(b); b.hidden = false; b.classList.remove('done'); });
    const cancel = () => MS.api(`/api/jobs/${id}/cancel`, { method: 'POST' }).catch(() => {});
    boxes.forEach(b => MS.$('.jb-cancel', b).addEventListener('click', cancel));
    MS.$$(`[data-run="${kind}"]`).forEach(b => (b.disabled = true));
    MS.emit('job:start', kind);
    let since = 0;
    let snap;
    try {
      while (true) {
        await MS.sleep(380);
        try { snap = await MS.api(`/api/jobs/${id}?since=${since}`); }
        catch (e) { await MS.sleep(800); continue; }
        since = snap.log_total;
        for (const line of snap.log) {
          boxes.forEach(b => b._term.write(line));
          MS.emit('log', { kind, line });
        }
        const pct = snap.progress;
        boxes.forEach(b => {
          MS.$('.jb-msg', b).textContent = snap.message || '…';
          MS.$('.jb-time', b).textContent = MS.fmtDuration(snap.elapsed);
          MS.$('.jb-pct', b).textContent = pct == null ? '' : Math.round(pct * 100) + '%';
          const bar = MS.$('.bar', b);
          bar.classList.toggle('indet', pct == null);
          MS.$('.bar-fill', b).style.width = pct == null ? '' : (pct * 100).toFixed(1) + '%';
        });
        if (snap.status !== 'running') break;
      }
    } finally {
      delete MS.running[kind];
      MS.$$(`[data-run="${kind}"]`).forEach(b => (b.disabled = false));
      boxes.forEach(b => b.classList.add('done'));
      MS.emit('job:end', kind);
    }
    const msg = { done: 'COMPLETADO', cancelled: 'CANCELADO', error: 'ERROR' }[snap.status];
    boxes.forEach(b => (MS.$('.jb-msg', b).textContent = `${msg} · ${MS.fmtDuration(snap.elapsed)}`));
    if (snap.status === 'error') { MS.toast(snap.error || 'Error', 'err'); return null; }
    if (snap.status !== 'done') return null;
    MS.state.results[kind] = snap.result;
    MS.emit('result:' + kind, snap.result);
    MS.emit('results', kind);
    return snap.result;
  };

  // Botones genéricos data-run
  document.addEventListener('click', ev => {
    const btn = ev.target.closest('[data-run]');
    if (!btn || btn.disabled) return;
    MS.runJob(btn.dataset.run);
  });

  // Animaciones de fondo y barra de estado mientras hay trabajos
  function refreshBusy() {
    const kinds = Object.keys(MS.running);
    window.MatrixRain && window.MatrixRain.setIntensity(kinds.length > 0);
    MS.$('#sb-jobs').textContent = kinds.length ? '▶ EN CURSO: ' + kinds.map(MS.jobLabel).join(' · ') : '';
    const views = { junk: 'disk', large: 'disk', duplicates: 'disk', programs: 'disk', processes: 'security', persistence: 'security', defender_status: 'security', defender_scan: 'security', virustotal: 'security', benchmark: 'perf' };
    const busyViews = new Set(kinds.map(k => views[k]));
    MS.$$('#nav button').forEach(b => b.classList.toggle('busy', busyViews.has(b.dataset.view)));
  }
  MS.on('job:start', refreshBusy);
  MS.on('job:end', refreshBusy);
})();
