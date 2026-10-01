/* Arranque: secuencia de inicio, navegación, reloj y carga de estado. */
(function () {
  'use strict';
  const { $, $$, esc } = MS;

  // ------------------------------------------------------------ navegación
  function show(view) {
    $$('#nav button').forEach(b => b.classList.toggle('active', b.dataset.view === view));
    $$('.view').forEach(v => v.classList.toggle('active', v.id === 'view-' + view));
    const section = $('#view-' + view);
    $$('.scramble', section).forEach(MS.scramble);
    $('#main').scrollTop = 0;
    try { localStorage.setItem('ms-view', view); } catch (_) { /* almacenamiento no disponible */ }
    MS.emit('view:' + view);
  }
  MS.show = show;

  // ------------------------------------------------------------ secuencia de inicio
  async function boot(sys) {
    const el = $('#boot');
    let skip = false;
    try { skip = sessionStorage.getItem('ms-booted') === '1'; } catch (_) { /* sin storage */ }
    if (skip || MS.reduceMotion) { el.remove(); return; }
    const pre = $('#boot-text');
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      el.classList.add('done');
      setTimeout(() => el.remove(), 750);
      try { sessionStorage.setItem('ms-booted', '1'); } catch (_) { /* sin storage */ }
    };
    el.addEventListener('click', finish);
    window.addEventListener('keydown', finish, { once: true });
    const lines = [
      '> MATRIXSCAN v' + (sys ? sys.version : '1.0') + ' — iniciando',
      '> enlace con el núcleo local ............... OK',
      '> módulo DISCO ............................. OK',
      '> módulo SEGURIDAD ......................... OK',
      '> módulo RENDIMIENTO ....................... OK',
      sys ? `> host: ${sys.hostname} · ${sys.os}` : '> host: desconocido',
      sys ? `> permisos: ${sys.admin ? 'ADMINISTRADOR' : 'usuario (análisis parcial)'}` : '',
      '',
    ];
    for (const line of lines) {
      if (done) return;
      for (let i = 0; i <= line.length; i += 2) {
        if (done) return;
        pre.textContent = pre.textContent.replace(/█$/, '') + line.slice(i, i + 2) + '█';
        await MS.sleep(9);
      }
      pre.textContent = pre.textContent.replace(/█$/, '') + '\n';
    }
    for (const w of ['Despierta...', 'La Matrix tiene tu disco.', 'Sigue al conejo blanco.']) {
      if (done) return;
      const span = document.createElement('span');
      span.className = 'wake';
      pre.appendChild(span);
      for (let i = 0; i <= w.length; i++) {
        if (done) return;
        span.textContent = w.slice(0, i) + '█';
        await MS.sleep(45);
      }
      span.textContent = w + '\n';
      await MS.sleep(380);
    }
    await MS.sleep(350);
    finish();
  }

  // ------------------------------------------------------------ reloj y cabecera
  function tick() {
    const d = new Date();
    $('#clock').textContent = d.toLocaleTimeString('es-CO', { hour12: false });
  }

  function renderTop(sys) {
    $('#ver').textContent = 'v' + sys.version;
    $('#top-meta').innerHTML = `
      <span>HOST <b>${esc(sys.hostname)}</b></span>
      <span>OS <b>${esc(sys.os)}</b></span>
      <span>CPU <b>${sys.cores_logical} hilos</b></span>
      <span class="pill ${sys.admin ? 'ok' : 'warn'}">${sys.admin ? 'ADMIN' : 'SIN ADMIN'}</span>`;
  }

  // ------------------------------------------------------------ inicio
  async function start() {
    MS.initDashboard();
    MS.initDisk();
    MS.initSecurity();
    MS.initPerf();
    MS.initSettings();

    $$('#nav button').forEach(b => b.addEventListener('click', () => show(b.dataset.view)));
    document.addEventListener('click', ev => {
      const a = ev.target.closest('[data-goto]');
      if (a) { ev.preventDefault(); show(a.dataset.goto); }
    });
    tick(); setInterval(tick, 1000);

    let sys = null;
    try {
      [sys, MS.state.config] = await Promise.all([MS.api('/api/system'), MS.api('/api/config')]);
    } catch (e) {
      MS.toast('No hay conexión con MatrixScan: ' + e.message, 'err');
    }
    boot(sys);
    if (sys) {
      MS.state.system = sys;
      renderTop(sys);
      MS.renderSystem(sys);
      MS.emit('system', sys);
      setInterval(async () => {
        try { MS.state.system = await MS.api('/api/system'); MS.renderSystem(MS.state.system); } catch (_) { /* reintenta */ }
      }, 30000);
    }
    if (MS.state.config) MS.emit('config', MS.state.config);

    // Resultados que el servidor ya tenía (si se recargó la página)
    try {
      const latest = await MS.api('/api/results');
      for (const [kind, entry] of Object.entries(latest)) {
        if (kind === 'virustotal') { Object.assign(MS.state.vt, entry.result.results); continue; }
        MS.state.results[kind] = entry.result;
        MS.emit('result:' + kind, entry.result);
      }
      if (Object.keys(latest).length) MS.emit('results', 'restore');
    } catch (_) { /* nada que restaurar */ }

    let view = 'dashboard';
    try { view = localStorage.getItem('ms-view') || view; } catch (_) { /* sin storage */ }
    show($('#view-' + view) ? view : 'dashboard');
    MS.mission.write('> sistema en línea. Pulsa INICIAR ESCANEO COMPLETO o elige una sección.');
  }

  start();
})();
