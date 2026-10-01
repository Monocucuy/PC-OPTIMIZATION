/* Vista RENDIMIENTO: telemetría en vivo, ranking de procesos y benchmark. */
(function () {
  'use strict';
  const { $, $$, esc, fmtBytes } = MS;
  let charts = {};
  let lastT = 0;
  let history = [];
  let candidates = [];
  const selected = new Set();
  let selectionTouched = false;
  const TESTS = {
    cpu_multi: { label: 'CPU multinúcleo', unit: 'MB/s', higher: true },
    cpu_single: { label: 'CPU un núcleo', unit: 'MB/s', higher: true },
    memory: { label: 'Memoria RAM', unit: 'GB/s', higher: true },
    disk_write: { label: 'Disco: escritura', unit: 'MB/s', higher: true },
    disk_latency: { label: 'Disco: latencia', unit: 'ms', higher: false },
  };

  // ------------------------------------------------------------ en vivo
  async function poll() {
    try {
      const live = await MS.api(`/api/perf/live?since=${lastT}`);
      $('.statusbar').classList.remove('offline');
      $('#sb-link').lastChild.textContent = ' ENLACE LOCAL';
      if (live.history.length) {
        history = history.concat(live.history).slice(-120);
        lastT = history[history.length - 1].t;
      }
      live.history = history;
      MS.state.live = live;
      MS.emit('live', live);
    } catch (e) {
      $('.statusbar').classList.add('offline');
      $('#sb-link').lastChild.textContent = ' SIN CONEXIÓN CON MATRIXSCAN';
    }
    setTimeout(poll, 1000);
  }

  function renderLive(live) {
    const h = live.history;
    if (!h.length) return;
    const s = h[h.length - 1];
    // barra lateral
    $('#nl-cpu').textContent = MS.fmtPct(s.cpu);
    $('#nl-ram').textContent = MS.fmtPct(s.ram);
    $('#nl-bg').textContent = MS.fmtPct(live.background.cpu, 1);
    $('#nl-cpu-bar').style.width = s.cpu + '%';
    $('#nl-ram-bar').style.width = s.ram + '%';
    // dashboard
    MS.dashCpu.setData(h); MS.dashRam.setData(h);
    $('#dash-cpu-v').textContent = MS.fmtPct(s.cpu);
    $('#dash-ram-v').textContent = `${MS.fmtPct(s.ram)} · ${fmtBytes(s.ram_used)} / ${fmtBytes(s.ram_total, 0)}`;
    // rendimiento (solo si la vista está visible)
    if (!$('#view-perf').classList.contains('active')) return;
    const rows = h.map(x => ({ ...x, disk: (x.disk_read + x.disk_write) / 1048576 }));
    charts.cpu.setData(rows); charts.ram.setData(rows); charts.disk.setData(rows);
    $('#pf-cpu-v').textContent = MS.fmtPct(s.cpu);
    $('#pf-ram-v').textContent = `${MS.fmtPct(s.ram)} · ${fmtBytes(s.ram_used)}`;
    $('#pf-disk-v').textContent = `L ${MS.fmtRate(s.disk_read)} · E ${MS.fmtRate(s.disk_write)}`;
    $('#pf-cores').innerHTML = s.cores.map(c => `<i style="height:${Math.max(3, c)}%" title="${c}%"></i>`).join('');
    const bg = live.background;
    stat('#pf-bg-cpu', MS.fmtPct(bg.cpu, 1), `${bg.count} procesos en 2º plano`, bg.cpu > 25 ? 'bad' : bg.cpu > 10 ? 'warn' : '');
    stat('#pf-bg-ram', fmtBytes(bg.rss), `${(bg.rss / s.ram_total * 100).toFixed(0)}% de la RAM total`);
    stat('#pf-disk', MS.fmtRate(s.disk_read + s.disk_write), 'lectura + escritura');
    stat('#pf-net', MS.fmtRate(s.net_recv + s.net_sent), `↓ ${MS.fmtRate(s.net_recv)} · ↑ ${MS.fmtRate(s.net_sent)}`);
    renderProcs(live.processes);
  }

  function stat(id, value, sub, cls = '') {
    const v = $(id + ' .stat-value');
    v.textContent = value; v.className = 'stat-value ' + cls;
    $(id + ' .stat-sub').textContent = sub;
  }

  let procTick = 0;
  function renderProcs(list) {
    if (procTick++ % 2) return; // cada 2 s basta
    const onlyBg = $('#pf-only-bg').checked;
    const rows = list.filter(p => !onlyBg || !p.foreground).slice(0, 15);
    const max = Math.max(...rows.map(p => p.cpu_avg), 1);
    const box = $('#pf-procs');
    box._tbl = box._tbl || { key: 'cpu_avg', dir: -1 };
    MS.table(box, rows, [
      { key: 'name', label: 'PROCESO', render: p => `<div class="name">${esc(p.name)}${p.count > 1 ? ` <span class="muted">×${p.count}</span>` : ''}</div>${p.service ? `<div class="path">servicio: ${esc(p.service)}</div>` : ''}` },
      { key: 'foreground', label: 'PLANO', render: p => MS.badge(p.foreground ? '1º plano' : '2º plano', p.foreground ? 'ok' : 'dim') },
      { key: 'cpu', label: 'CPU AHORA', cls: 'num', render: p => MS.fmtPct(p.cpu, 1) },
      { key: 'cpu_avg', label: 'CPU 60 S', cls: 'num', render: p => MS.fmtPct(p.cpu_avg, 1) },
      { key: 'bar', label: '', sortable: false, cls: 'bar-cell', render: p => MS.meter(p.cpu_avg / max * 100, p.cpu_avg > 15 ? 'warn' : '') },
      { key: 'rss', label: 'RAM', cls: 'num', render: p => fmtBytes(p.rss) },
      { key: 'io', label: 'DISCO', cls: 'num', render: p => MS.fmtRate(p.io) },
    ]);
  }

  // ------------------------------------------------------------ benchmark
  async function loadCandidates() {
    try {
      const data = await MS.api('/api/perf/candidates');
      candidates = data.candidates;
      if (!selectionTouched) {
        selected.clear();
        candidates.filter(c => c.suggested).forEach(c => selected.add(c.name));
      }
      renderCandidates();
    } catch (e) { MS.toast(e.message, 'err'); }
  }

  function renderCandidates() {
    const box = $('#bench-candidates');
    if (!candidates.length) {
      box.innerHTML = '<div class="empty" style="grid-column:1/-1">> Ningún proceso en 2º plano consume lo suficiente para medirlo. El benchmark hará solo la medición base.</div>';
      return;
    }
    box.innerHTML = candidates.map(c => `
      <label class="cand ${c.blocked ? 'blocked' : ''}" title="${esc(c.blocked || (c.foreground ? 'Tiene ventana abierta: al pausarlo se congelará unos segundos' : 'Proceso en segundo plano'))}">
        <input type="checkbox" value="${esc(c.name)}" ${c.blocked ? 'disabled' : ''} ${selected.has(c.name) && !c.blocked ? 'checked' : ''}>
        <span><span class="cn">${esc(c.name)}${c.count > 1 ? ` ×${c.count}` : ''}</span><br><span class="cs">${esc(c.blocked || (c.foreground ? '1º plano' : c.service ? 'servicio' : '2º plano'))}</span></span>
        <span class="ci">${MS.fmtPct(c.cpu_avg, 1)} CPU<br>${fmtBytes(c.rss)}</span>
      </label>`).join('');
    $$('input', box).forEach(i => i.addEventListener('change', () => {
      selectionTouched = true;
      if (i.checked) selected.add(i.value); else selected.delete(i.value);
    }));
  }

  async function runBench() {
    const names = [...selected].filter(n => candidates.some(c => c.name === n && !c.blocked));
    $('#bench-resume').hidden = !names.length;
    try {
      await MS.runJob('benchmark', { names });
    } finally {
      $('#bench-resume').hidden = true;
      loadCandidates();
    }
  }

  function renderBench(r) {
    const box = $('#bench-results');
    let html = '';
    if (r.loss_pct != null) {
      const l = r.loss_pct;
      const cls = l > 15 ? 'bad' : l > 5 ? 'warn' : '';
      const sig = r.comparison.filter(c => c.significant && c.gain_pct > 0);
      html += `<div class="verdict">
        <div class="loss ${cls}" id="bench-loss">0%</div>
        <div><b>${l > 0.5 ? `Tus procesos en segundo plano te quitan ~${l}% de rendimiento.` : 'Los procesos pausados no afectan de forma medible el rendimiento.'}</b>
        <p class="muted small" style="margin-top:6px">Promedio ponderado (CPU 55%, disco 35%, RAM 10%) de las pruebas con diferencia mayor al margen de error.
        ${sig.length ? 'Más afectado: ' + sig.sort((a, b) => b.gain_pct - a.gain_pct).map(c => `${esc(c.label)} (+${c.gain_pct}%)`).join(', ') + '.' : ''}</p>
        ${r.failed.length ? `<p class="muted small">No se pudieron pausar: ${r.failed.map(esc).join(', ')}</p>` : ''}</div>
      </div>
      <div class="legend"><span><i style="background:var(--g-dim)"></i>con todo activo</span><span><i style="background:var(--g)"></i>con procesos en pausa</span></div>`;
      html += r.comparison.map(c => {
        // En latencia menos es mejor: se dibuja la inversa para que barra más larga = mejor
        const inv = c.unit === 'ms';
        const vb = inv ? 1 / c.base : c.base, vp = inv ? 1 / c.paused : c.paused;
        const max = Math.max(vb, vp);
        const fmt = v => (c.unit === 'ms' ? v.toFixed(2) : v.toFixed(c.unit === 'GB/s' ? 2 : 0)) + ' ' + c.unit;
        return `<div class="cmp">
          <span>${esc(c.label)}<br><span class="muted small">${fmt(c.base)} → ${fmt(c.paused)}</span></span>
          <div class="bars">${MS.meter(vb / max * 100, 'base')}${MS.meter(vp / max * 100)}</div>
          <span class="delta ${c.significant ? (c.gain_pct > 0 ? 'up' : '') : 'ns'}" title="margen de error ±${c.noise_pct}%">${c.gain_pct > 0 ? '+' : ''}${c.gain_pct}%${c.significant ? '' : ' ~'}</span>
        </div>`;
      }).join('');
      html += '<p class="muted small">"~" = diferencia dentro del margen de error (no significativa). Barra más larga = mejor (en latencia se grafica la inversa).</p>';
      if (r.attribution.length) {
        html += `<h2 style="margin-top:16px">// QUIÉN CONSUME MÁS (CPU PROMEDIO)</h2>` + r.attribution.map(a => `
          <div class="cmp"><span class="name">${esc(a.name)}</span>${MS.meter(a.share_pct)}<span class="delta">${a.share_pct}%</span></div>`).join('');
      }
    } else {
      const prev = (r.history || []).slice(-2, -1)[0];
      html += `<div class="note info">Medición base sin pausar procesos (no había procesos seleccionados). Sirve para comparar antes y después de limpiar${prev ? '; se compara con tu medición anterior' : ''}.</div>`;
      html += Object.entries(r.baseline).map(([k, v]) => {
        const t = TESTS[k];
        const old = prev && prev.scores[k];
        let delta = '';
        if (old) {
          const d = t.higher ? (v.value - old) / old * 100 : (old - v.value) / old * 100;
          delta = `<span class="delta ${Math.abs(d) > 5 ? (d > 0 ? 'up' : '') : 'ns'}">${d > 0 ? '+' : ''}${d.toFixed(1)}%</span>`;
        }
        return `<div class="cmp"><span>${esc(t.label)}</span><span class="name">${v.value.toFixed(t.unit === 'MB/s' ? 0 : 2)} ${t.unit}</span>${delta || '<span></span>'}</div>`;
      }).join('');
    }
    const hist = (r.history || []).slice(-8).reverse();
    if (hist.length > 1) {
      html += `<h2 style="margin-top:18px">// HISTORIAL</h2><div id="bench-hist"></div>`;
    }
    box.innerHTML = html;
    const lossEl = $('#bench-loss');
    if (lossEl) MS.countUp(lossEl, r.loss_pct, v => '-' + v.toFixed(1) + '%', 1400);
    if (hist.length > 1) {
      MS.table($('#bench-hist'), hist, [
        { key: 'timestamp', label: 'FECHA', render: h => MS.fmtDate(h.timestamp) },
        { key: 'loss_pct', label: 'PÉRDIDA', cls: 'num', render: h => (h.loss_pct == null ? '--' : h.loss_pct + '%') },
        { key: 'cpu', label: 'CPU MULTI', cls: 'num', render: h => h.scores.cpu_multi.toFixed(0) + ' MB/s', sort: h => h.scores.cpu_multi },
        { key: 'disk', label: 'DISCO', cls: 'num', render: h => h.scores.disk_write.toFixed(0) + ' MB/s', sort: h => h.scores.disk_write },
        { key: 'paused', label: 'PAUSADOS', sortable: false, render: h => `<span class="path">${esc((h.paused || []).join(', ') || '--')}</span>` },
      ], { sortKey: 'timestamp' });
    }
  }

  // ------------------------------------------------------------ init
  MS.initPerf = function () {
    const pct = v => v.toFixed(0) + '%';
    charts.cpu = new LineChart($('#pf-cpu'), { series: [{ key: 'cpu', color: '#00ff41' }], max: 100, format: pct, points: 120 });
    charts.ram = new LineChart($('#pf-ram'), { series: [{ key: 'ram', color: '#00ff41' }], max: 100, format: pct, points: 120 });
    charts.disk = new LineChart($('#pf-diskc'), { series: [{ key: 'disk', color: '#7dffa6' }], format: v => v.toFixed(v < 10 ? 1 : 0) + 'M', points: 120 });
    MS.on('live', renderLive);
    MS.on('result:benchmark', renderBench);
    MS.on('view:perf', () => { loadCandidates(); Object.values(charts).forEach(c => c._resize()); });
    $('#pf-only-bg').addEventListener('change', () => { procTick = 0; MS.state.live && renderProcs(MS.state.live.processes); });
    $('#bench-refresh').addEventListener('click', () => { selectionTouched = false; loadCandidates(); });
    $('#bench-run').addEventListener('click', runBench);
    $('#bench-resume').addEventListener('click', async () => {
      try {
        const r = await MS.api('/api/perf/resume', { method: 'POST' });
        MS.toast(`${r.resumed} procesos reanudados.`);
      } catch (e) { MS.toast(e.message, 'err'); }
    });
    MS.on('job:start', k => { if (k === 'benchmark') $('#bench-run').disabled = true; });
    MS.on('job:end', k => { if (k === 'benchmark') $('#bench-run').disabled = false; });
    poll();
  };
})();
