/* Vista NÚCLEO: salud global, escaneo completo, telemetría y reporte. */
(function () {
  'use strict';
  const { $, esc, fmtBytes } = MS;
  const FULL_SCAN = ['junk', 'large', 'programs', 'processes', 'persistence', 'defender_status'];
  const R = () => MS.state.results;

  // ------------------------------------------------------------ salud
  /** Calcula 0-100 a partir de los resultados disponibles. Cada descuento queda explicado. */
  MS.computeHealth = function () {
    const r = R();
    const live = MS.state.live;
    const sys = MS.state.system;
    const parts = [];
    let score = 100;
    let evidence = 0;
    // destino de cada observación: sección, pestaña y elemento que se resalta
    const GO = {
      drives: { goto: 'dashboard', target: '#dash-disks' },
      junk: { goto: 'disk', tab: 'junk', target: '#junk-results' },
      large: { goto: 'disk', tab: 'large', target: '#large-results' },
      dups: { goto: 'disk', tab: 'duplicates', target: '#duplicates-results' },
      progs: { goto: 'disk', tab: 'programs', target: '#programs-results' },
      procs: { goto: 'security', target: '#processes-results' },
      startup: { goto: 'security', target: '#persistence-results' },
      defender: { goto: 'security', target: '#defender-results' },
      cpu: { goto: 'perf', target: '#pf-procs' },
      ram: { goto: 'perf', target: '#pf-ram' },
      bench: { goto: 'perf', target: '#bench-results' },
    };
    const ded = (pts, text, go) => { if (pts) { score -= pts; parts.push({ pts: -pts, text, go }); } };

    if (sys && sys.disks && sys.disks.length) {
      const d = sys.disks.find(x => /^c:/i.test(x.mount)) || sys.disks[0];
      if (d.percent >= 95) ded(20, `Disco ${d.mount} casi lleno (${d.percent.toFixed(0)}%)`, GO.drives);
      else if (d.percent >= 85) ded(10, `Disco ${d.mount} al ${d.percent.toFixed(0)}%`, GO.drives);
    }
    if (r.junk) {
      evidence++;
      const gb = r.junk.total / 1024 ** 3;
      if (gb >= 1) ded(Math.min(15, Math.round(gb * 1.5)), `${gb.toFixed(1)} GB de basura acumulada`, GO.junk);
    }
    if (r.large && r.large.total > 5 * 1024 ** 3) { evidence++; ded(5, `${fmtBytes(r.large.total)} en archivos grandes sin usar`, GO.large); }
    if (r.duplicates && r.duplicates.wasted > 2 * 1024 ** 3) ded(5, `${fmtBytes(r.duplicates.wasted)} en duplicados`, GO.dups);
    if (r.programs && r.programs.supported && r.programs.unused_count >= 5) ded(5, `${r.programs.unused_count} programas sin uso`, GO.progs);

    let high = 0, med = 0;
    for (const k of ['processes', 'persistence']) {
      if (r[k] && r[k].counts) { evidence++; high += r[k].counts.alto; med += r[k].counts.medio; }
    }
    // lleva a la tabla donde hay más riesgo: procesos o arranque
    const heat = k => (r[k] && r[k].counts ? r[k].counts.alto * 2 + r[k].counts.medio : 0);
    const riskGo = heat('processes') >= heat('persistence') ? GO.procs : GO.startup;
    if (high) ded(Math.min(40, high * 20), `${high} elemento(s) de riesgo ALTO`, riskGo);
    if (med) ded(Math.min(20, med * 6), `${med} elemento(s) de riesgo medio`, riskGo);
    const vtBad = Object.values(MS.state.vt).filter(v => v && v.verdict === 'malicioso').length;
    if (vtBad) ded(40, `${vtBad} archivo(s) marcados como maliciosos en VirusTotal`, GO.procs);

    const df = r.defender_scan || r.defender_status;
    if (df && df.supported) {
      evidence++;
      const otherAv = (df.products || []).some(p => p.enabled && !/defender/i.test(p.name));
      if (!df.realtime && !otherAv) ded(25, 'Protección en tiempo real desactivada', GO.defender);
      if (df.sig_age_days != null && df.sig_age_days > 7) ded(10, `Firmas del antivirus con ${df.sig_age_days} días`, GO.defender);
      const active = (df.threats || []).filter(t => t.active).length;
      if (active) ded(30, `${active} amenaza(s) activa(s) según Defender`, GO.defender);
    }
    if (live) {
      if (live.background.cpu > 25) ded(10, `Procesos en 2º plano usan ${live.background.cpu.toFixed(0)}% de CPU`, GO.cpu);
      else if (live.background.cpu > 10) ded(5, `Procesos en 2º plano usan ${live.background.cpu.toFixed(0)}% de CPU`, GO.cpu);
      const ram = live.history.length ? live.history[live.history.length - 1].ram : 0;
      if (ram > 90) ded(10, `RAM al ${ram.toFixed(0)}%`, GO.ram);
      else if (ram > 80) ded(5, `RAM al ${ram.toFixed(0)}%`, GO.ram);
    }
    if (r.persistence && r.persistence.startup_programs > 12) ded(5, `${r.persistence.startup_programs} programas arrancan con Windows`, GO.startup);
    const bench = r.benchmark;
    if (bench && bench.loss_pct != null) {
      evidence++;
      if (bench.loss_pct > 15) ded(10, `Pierdes ~${bench.loss_pct}% de rendimiento por procesos en 2º plano`, GO.bench);
      else if (bench.loss_pct > 5) ded(5, `Pierdes ~${bench.loss_pct}% de rendimiento por procesos en 2º plano`, GO.bench);
    }
    if (!evidence) return null;
    score = Math.max(0, Math.min(100, Math.round(score)));
    const label = score >= 85 ? 'ÓPTIMO' : score >= 65 ? 'ESTABLE' : score >= 40 ? 'COMPROMETIDO' : 'CRÍTICO';
    return { score, label, parts };
  };

  /** Observación del diagnóstico: enlace al detalle si tiene destino. */
  function obsLink(p) {
    const g = p.go;
    if (!g) return esc(p.text);
    return `<a class="obs-link" href="#" data-goto="${g.goto}"${g.tab ? ` data-tab="${g.tab}"` : ''}${g.target ? ` data-target="${g.target}"` : ''}>${esc(p.text)} <span class="arrow">→</span></a>`;
  }

  let lastScore = null;
  function renderHealth() {
    const h = MS.computeHealth();
    const ring = $('#health-ring');
    const val = $('#health-value');
    const list = $('#health-breakdown');
    if (!h) return;
    const C = 2 * Math.PI * 88;
    ring.style.strokeDasharray = C.toFixed(1);
    ring.style.strokeDashoffset = (C * (1 - h.score / 100)).toFixed(1);
    ring.classList.toggle('warn', h.score < 65 && h.score >= 40);
    ring.classList.toggle('bad', h.score < 40);
    if (h.score !== lastScore) { MS.countUp(val, h.score); lastScore = h.score; }
    $('#health-label').textContent = h.label;
    list.innerHTML = h.parts.length
      ? h.parts.map(p => `<li><b>${p.pts}</b> ${obsLink(p)}</li>`).join('')
      : '<li class="good"><b>OK</b> Sin problemas con los datos actuales</li>';
  }

  // ------------------------------------------------------------ tarjetas
  function setStat(id, value, sub, cls = '') {
    const el = $(id);
    const v = $('.stat-value', el);
    v.className = 'stat-value ' + cls;
    if (typeof value === 'number') MS.countUp(v, value, x => x.toFixed(value % 1 ? 1 : 0));
    else v.textContent = value;
    $('.stat-sub', el).textContent = sub;
  }

  function renderStats() {
    const r = R();
    if (r.junk) {
      const gb = r.junk.total / 1024 ** 3;
      const el = $('#stat-junk .stat-value');
      el.className = 'stat-value ' + (gb > 10 ? 'warn' : '');
      MS.countUp(el, r.junk.total, v => fmtBytes(v));
      $('#stat-junk .stat-sub').textContent = `${fmtBytes(r.junk.safe_total)} seguro de limpiar`;
    }
    if (r.processes || r.persistence) {
      let high = 0, med = 0, low = 0;
      for (const k of ['processes', 'persistence']) if (r[k] && r[k].counts) { high += r[k].counts.alto; med += r[k].counts.medio; low += r[k].counts.bajo; }
      setStat('#stat-threats', high + med, `${high} alto · ${med} medio · ${low} bajo`, high ? 'bad' : med ? 'warn' : '');
    }
    if (r.benchmark && r.benchmark.loss_pct != null) {
      const l = r.benchmark.loss_pct;
      const el = $('#stat-bench .stat-value');
      el.className = 'stat-value ' + (l > 15 ? 'bad' : l > 5 ? 'warn' : '');
      MS.countUp(el, l, v => '-' + v.toFixed(1) + '%');
      $('#stat-bench .stat-sub').textContent = `por ${r.benchmark.paused_procs.length} proceso(s) en 2º plano`;
    }
  }

  function renderLive(live) {
    const bg = live.background;
    const el = $('#stat-bg .stat-value');
    el.textContent = MS.fmtPct(bg.cpu, 1) + ' CPU';
    el.className = 'stat-value ' + (bg.cpu > 25 ? 'bad' : bg.cpu > 10 ? 'warn' : '');
    $('#stat-bg .stat-sub').textContent = `${fmtBytes(bg.rss)} RAM · ${bg.count} procesos`;
  }

  // ------------------------------------------------------------ sistema
  MS.renderSystem = function (sys) {
    const dd = (k, v) => `<dt>${esc(k)}</dt><dd>${v}</dd>`;
    $('#dash-sys').innerHTML = [
      dd('EQUIPO', esc(sys.hostname)),
      dd('SISTEMA', esc(sys.os)),
      dd('CPU', `${esc(sys.cpu)} · ${sys.cores_physical}C/${sys.cores_logical}T`),
      dd('RAM', fmtBytes(sys.ram_total, 0)),
      dd('ENCENDIDO', MS.fmtDuration(sys.uptime_s)),
      dd('PERMISOS', sys.admin ? '<span class="pill ok">ADMINISTRADOR</span>' : '<span class="pill warn">USUARIO</span> <span class="muted small">— abre con iniciar.bat y acepta el permiso para análisis completo</span>'),
    ].join('');
    $('#dash-disks').innerHTML = sys.disks.map(d => {
      const cls = d.percent >= 90 ? 'bad' : d.percent >= 80 ? 'warn' : '';
      return `<div class="disk-row"><span class="mount">${esc(d.mount)}</span>${MS.meter(d.percent, cls)}<span class="dinfo">${fmtBytes(d.free)} libres de ${fmtBytes(d.total, 0)}</span></div>`;
    }).join('') || '<p class="muted">Sin unidades.</p>';
  };

  // ------------------------------------------------------------ escaneo completo
  async function fullScan() {
    const btn = $('#btn-fullscan');
    btn.disabled = true;
    const box = $('#full-box');
    try {
      MS.mission.write('> ===== ESCANEO COMPLETO INICIADO =====');
      for (let i = 0; i < FULL_SCAN.length; i++) {
        const kind = FULL_SCAN[i];
        MS.mission.write(`> PASO ${i + 1}/${FULL_SCAN.length}: ${MS.jobLabel(kind)}`);
        if (MS.running[kind]) { MS.mission.write('  (ya estaba en curso, se omite)'); continue; }
        await MS.runJob(kind, {}, { box });
      }
      MS.mission.write('> ===== ESCANEO COMPLETO TERMINADO =====');
      const msg = $('.jb-msg', box);
      if (msg) msg.textContent = `ESCANEO COMPLETO TERMINADO · ${FULL_SCAN.length} módulos`;
      const h = MS.computeHealth();
      if (h) MS.toast(`Escaneo terminado. Salud del sistema: ${h.score}/100 (${h.label})`);
    } finally {
      btn.disabled = false;
    }
  }

  // ------------------------------------------------------------ reporte
  function exportReport() {
    const r = R(), sys = MS.state.system || {}, h = MS.computeHealth();
    const L = [];
    const line = (s = '') => L.push(s);
    line('MATRIX//SCAN — REPORTE DEL SISTEMA');
    line('Generado: ' + new Date().toLocaleString('es-CO'));
    line(`Equipo: ${sys.hostname || '?'} · ${sys.os || ''} · ${sys.cpu || ''}`);
    line(h ? `Salud: ${h.score}/100 (${h.label})` : 'Salud: sin datos');
    if (h) h.parts.forEach(p => line(`  ${p.pts}  ${p.text}`));
    if (r.junk) {
      line(); line(`== BASURA: ${fmtBytes(r.junk.total)} (seguro: ${fmtBytes(r.junk.safe_total)})`);
      r.junk.categories.forEach(c => line(`  [${c.risk}] ${c.name}: ${fmtBytes(c.size)} — ${c.how_to_clean}`));
    }
    if (r.large) {
      line(); line(`== ARCHIVOS GRANDES SIN USO: ${r.large.count || 0} (${fmtBytes(r.large.total)})`);
      (r.large.files || []).slice(0, 30).forEach(f => line(`  ${fmtBytes(f.size).padStart(9)}  ${MS.fmtDays(f.days_unused)} sin usar  ${f.path}`));
    }
    if (r.duplicates) {
      line(); line(`== DUPLICADOS: ${r.duplicates.group_count} grupos, recuperable ${fmtBytes(r.duplicates.wasted)}`);
      r.duplicates.groups.slice(0, 20).forEach(g => { line(`  ${fmtBytes(g.size)} × ${g.count}`); g.paths.forEach(p => line('     ' + p)); });
    }
    if (r.programs && r.programs.supported) {
      line(); line(`== PROGRAMAS SIN USO: ${r.programs.unused_count} (${fmtBytes(r.programs.unused_size)})`);
      r.programs.programs.filter(p => ['sin_uso', 'sin_registro'].includes(p.status)).slice(0, 40)
        .forEach(p => line(`  ${fmtBytes(p.size).padStart(9)}  ${p.name}  (${p.last_used ? MS.fmtAgo(p.last_used) : 'sin registro de uso'})`));
    }
    for (const [k, title] of [['processes', 'PROCESOS'], ['persistence', 'ARRANQUE']]) {
      const items = r[k] && (r[k].processes || r[k].entries);
      if (!items) continue;
      line(); line(`== ${title} SOSPECHOSOS`);
      const sus = items.filter(x => x.level !== 'ok');
      if (!sus.length) line('  Ninguno.');
      sus.forEach(x => {
        line(`  [${x.level.toUpperCase()} ${x.score}] ${x.name}  ${x.path || ''}`);
        x.reasons.forEach(re => line(`      - ${re.text}`));
        const vt = MS.state.vt[x.path];
        if (vt && vt.found) line(`      VirusTotal: ${vt.malicious}/${vt.engines} (${vt.verdict})`);
      });
    }
    const df = r.defender_scan || r.defender_status;
    if (df && df.supported) {
      line(); line('== WINDOWS DEFENDER');
      line(`  Tiempo real: ${df.realtime ? 'activo' : 'INACTIVO'} · Firmas: ${df.sig_age_days ?? '?'} días · Detecciones: ${(df.threats || []).length}`);
    }
    if (r.benchmark) {
      line(); line('== BENCHMARK');
      if (r.benchmark.loss_pct != null) line(`  Rendimiento perdido por procesos en 2º plano: ~${r.benchmark.loss_pct}%`);
      (r.benchmark.comparison || []).forEach(c => line(`  ${c.label}: ${c.gain_pct > 0 ? '+' : ''}${c.gain_pct}% al pausar ${c.significant ? '' : '(dentro del margen de error)'}`));
    }
    const blob = new Blob([L.join('\r\n')], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `MatrixScan-reporte-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ------------------------------------------------------------ bloque "qué hace"
  function renderAbout() {
    const sys = MS.state.system, cfg = MS.state.config;
    const notes = [];
    if (sys && !sys.admin) {
      notes.push('<div class="note">Estás sin permisos de administrador: el análisis de procesos y de programas saldrá incompleto. Cierra MatrixScan y abre <b>iniciar.bat</b> aceptando el permiso.</div>');
    }
    if (cfg && !cfg.has_vt_key) {
      notes.push('<div class="note info">VirusTotal sin configurar (opcional). Pega tu API key gratis en <a href="#" data-goto="settings">CONFIG</a> para confirmar los sospechosos.</div>');
    }
    $('#about-status').innerHTML = notes.join('');
  }

  // ------------------------------------------------------------ init
  MS.initDashboard = function () {
    const about = $('#about');
    try { if (localStorage.getItem('ms-about') === 'closed') about.open = false; } catch (_) { /* sin storage */ }
    about.addEventListener('toggle', () => {
      try { localStorage.setItem('ms-about', about.open ? 'open' : 'closed'); } catch (_) { /* sin storage */ }
    });
    MS.on('system', renderAbout);
    MS.on('config', renderAbout);
    $('#about-scan').addEventListener('click', () => {
      $('#main').scrollTop = 0;          // el progreso del escaneo aparece arriba, en el anillo de salud
      $('#btn-fullscan').click();
    });

    MS.mission = new MS.Terminal($('#mission-log'), 300);
    MS.on('log', ({ kind, line }) => MS.mission.write(line, MS.jobLabel(kind)));
    MS.on('results', () => { renderStats(); renderHealth(); });
    MS.on('live', live => { renderLive(live); });
    setInterval(renderHealth, 5000);
    MS.dashCpu = new LineChart($('#dash-cpu'), { series: [{ key: 'cpu', color: '#00ff41' }], max: 100, format: v => v.toFixed(0) + '%' });
    MS.dashRam = new LineChart($('#dash-ram'), { series: [{ key: 'ram', color: '#00ff41' }], max: 100, format: v => v.toFixed(0) + '%' });
    $('#btn-fullscan').addEventListener('click', fullScan);
    $('#btn-export').addEventListener('click', exportReport);
    renderStats();
  };
})();
