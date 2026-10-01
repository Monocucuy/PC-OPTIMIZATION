/* Vista SEGURIDAD: Defender, heurística de procesos, arranque y VirusTotal. */
(function () {
  'use strict';
  const { $, esc, fmtBytes } = MS;
  const LEVEL = { alto: 'ALTO', medio: 'MEDIO', bajo: 'BAJO', ok: 'OK' };

  // ------------------------------------------------------------ VirusTotal
  function vtCell(path) {
    if (!path) return '';
    const v = MS.state.vt[path];
    if (v && v.error) return `<span class="vt-res muted" title="${esc(v.error)}">error</span>`;
    if (v && v.found) {
      return `<a class="vt-res" href="${esc(v.link)}" target="_blank" rel="noopener noreferrer" title="${esc(v.label || '')}">${MS.badge(`${v.malicious}/${v.engines}`, v.verdict)}</a>`;
    }
    if (v && !v.found) return `<a class="vt-res" href="${esc(v.link)}" target="_blank" rel="noopener noreferrer">${MS.badge('NO CONOCIDO', 'dim')}</a>`;
    if (!MS.state.config || !MS.state.config.has_vt_key) return '';
    return `<button class="btn btn-xs" data-vt="${esc(path)}" title="Consultar el hash en VirusTotal">[ VT ]</button>`;
  }

  async function vtLookup(paths) {
    if (!MS.state.config || !MS.state.config.has_vt_key) {
      MS.toast('Configura tu API key de VirusTotal en CONFIG.', 'err');
      return;
    }
    const res = await MS.runJob('virustotal', { paths });
    if (!res) return;
    Object.assign(MS.state.vt, res.results);
    const bad = Object.values(res.results).filter(v => v.verdict === 'malicioso' || v.verdict === 'sospechoso').length;
    MS.toast(bad ? `VirusTotal: ${bad} archivo(s) marcados por antivirus. Revísalos.` : 'VirusTotal: ningún archivo marcado como malicioso.', bad ? 'err' : '');
    rerender();
    MS.emit('results', 'virustotal');
  }

  function suspiciousPaths() {
    const r = MS.state.results;
    const items = [...((r.processes && r.processes.processes) || []), ...((r.persistence && r.persistence.entries) || [])];
    return [...new Set(items.filter(x => x.level !== 'ok' && x.path && !MS.state.vt[x.path]).map(x => x.path))];
  }

  function renderVtBanner() {
    const el = $('#vt-banner');
    const cfg = MS.state.config;
    if (!cfg) return;
    if (!cfg.has_vt_key) {
      el.innerHTML = '<div class="note">VirusTotal no está configurado. Crea una API key gratis y pégala en <a href="#" data-goto="settings">CONFIG</a> para confirmar los sospechosos con más de 70 antivirus.</div>';
      return;
    }
    const pending = suspiciousPaths();
    el.innerHTML = `<div class="note info" style="display:flex;gap:14px;align-items:center;flex-wrap:wrap">
      <span style="flex:1">VirusTotal activo (${esc(cfg.vt_key_hint)}). ${pending.length ? `${pending.length} archivo(s) sospechoso(s) sin consultar.` : 'Sin pendientes.'} Límite gratuito: 4 consultas/min.</span>
      ${pending.length ? `<button class="btn btn-xs" id="vt-bulk">[ CONSULTAR ${Math.min(pending.length, 20)} SOSPECHOSOS ]</button>` : ''}
    </div>`;
    const bulk = $('#vt-bulk');
    if (bulk) bulk.addEventListener('click', () => vtLookup(pending.slice(0, 20)));
  }

  // ------------------------------------------------------------ Defender
  function ageLight(label, days, warnAt, badAt, never) {
    if (days == null) return `<div class="light ${never ? 'warn' : ''}"><i></i><div><span class="lk">${label}</span>${never || '--'}</div></div>`;
    const cls = days >= badAt ? 'off' : days >= warnAt ? 'warn' : '';
    return `<div class="light ${cls}"><i></i><div><span class="lk">${label}</span>${days === 0 ? 'hoy' : `hace ${days} día(s)`}</div></div>`;
  }

  function renderDefender(r) {
    const box = $('#defender-results');
    if (!r.supported) { box.innerHTML = '<div class="empty">> Windows Defender solo existe en Windows.</div>'; return; }
    const light = (label, on, txtOn, txtOff) => `<div class="light ${on ? '' : 'off'}"><i></i><div><span class="lk">${label}</span>${on ? txtOn : txtOff}</div></div>`;
    const others = (r.products || []).filter(p => !/defender/i.test(p.name));
    let html = '';
    if (r.available) {
      html += `<div class="lights">
        ${light('ANTIVIRUS', r.antivirus, 'ACTIVO', 'INACTIVO')}
        ${light('TIEMPO REAL', r.realtime, 'ACTIVO', 'INACTIVO')}
        ${light('ANTIALTERACIONES', r.tamper, 'ACTIVA', 'INACTIVA')}
        ${ageLight('FIRMAS', r.sig_age_days, 3, 8)}
        ${ageLight('ESCANEO RÁPIDO', r.quick_scan_age_days, 8, 31, 'nunca')}
        ${ageLight('ESCANEO COMPLETO', r.full_scan_age_days, 60, 180, 'nunca')}
      </div>`;
      if (r.mode && !/normal/i.test(r.mode)) html += `<div class="note">Defender está en modo "${esc(r.mode)}": otro antivirus tiene el control.</div>`;
    } else {
      html += '<div class="note">No se pudo leer el estado de Defender. Puede estar desactivado porque hay otro antivirus instalado.</div>';
    }
    if (others.length) {
      html += `<p class="muted small">OTROS ANTIVIRUS REGISTRADOS: ${others.map(p => `${esc(p.name)} ${MS.badge(p.enabled ? 'activo' : 'inactivo', p.enabled ? 'ok' : 'medio')}`).join(' · ')}</p>`;
    }
    if (r.scan_exit_code != null) {
      html += r.scan_found_threats
        ? '<div class="note" style="border-color:var(--red);color:var(--red)">El escaneo rápido encontró amenazas. Abre "Seguridad de Windows" → Protección antivirus para ver las acciones.</div>'
        : '<div class="allclear">ESCANEO RÁPIDO LIMPIO<small>Defender no encontró amenazas.</small></div>';
    }
    const threats = r.threats || [];
    html += `<h2 style="margin-top:16px">// HISTORIAL DE DETECCIONES (${threats.length})</h2>`;
    html += threats.length ? '<div id="threat-table"></div>' : '<p class="muted small">Defender no tiene detecciones registradas.</p>';
    box.innerHTML = html;
    if (threats.length) {
      MS.table($('#threat-table'), threats, [
        { key: 'time', label: 'FECHA', render: t => esc(t.time ? new Date(t.time).toLocaleString('es-CO') : '--') },
        { key: 'name', label: 'AMENAZA', render: t => `<span class="name">${esc(t.name)}</span>` },
        { key: 'severity', label: 'SEVERIDAD', render: t => MS.badge(t.severity_label, t.severity >= 4 ? 'alto' : t.severity >= 2 ? 'medio' : 'bajo') },
        { key: 'active', label: 'ESTADO', render: t => (t.active ? MS.badge('ACTIVA', 'alto') : MS.badge(t.action_ok ? 'RESUELTA' : 'REVISAR', t.action_ok ? 'ok' : 'medio')) },
        { key: 'resources', label: 'ARCHIVO', sortable: false, render: t => `<div class="path">${(t.resources || []).map(esc).join('<br>')}</div>` },
      ], { sortKey: 'time' });
    }
  }

  // ------------------------------------------------------------ procesos
  const reasonChips = list => `<div class="chips">${list.map(r => `<span class="chip ${r.weight >= 4 ? 'r' : r.weight >= 2 ? 'w' : ''}" title="peso ${r.weight}">${esc(r.text)}</span>`).join('')}</div>`;
  const sigCell = x => (x.signer ? `<span class="name">${esc(x.signer)}</span>` : x.sig_status === 'NotSigned' ? MS.badge('SIN FIRMA', 'medio') : x.sig_status && x.sig_status !== 'N/A' ? `<span class="muted small">${esc(x.sig_status)}</span>` : '<span class="muted">--</span>');

  function renderProcesses(r) {
    const box = $('#processes-results');
    const all = $('#proc-all').checked;
    const rows = r.processes.filter(p => all || p.level !== 'ok');
    let html = `<div class="summary-row">
      <div><div class="big" style="color:var(--red)">${r.counts.alto}</div><div class="lbl">RIESGO ALTO</div></div>
      <div><div class="big" style="color:var(--amber)">${r.counts.medio}</div><div class="lbl">MEDIO</div></div>
      <div><div class="big">${r.counts.bajo}</div><div class="lbl">BAJO</div></div>
      <div><div class="big">${r.total}</div><div class="lbl">PROCESOS ANALIZADOS</div></div>
    </div>`;
    if (r.no_access) html += `<div class="note info">${r.no_access} procesos protegidos del sistema no se pudieron inspeccionar${MS.state.system && MS.state.system.admin ? '' : ' (abre como administrador para verlos)'}.</div>`;
    if (!rows.length) {
      html += '<div class="allclear">NINGÚN PROCESO SOSPECHOSO<small>La heurística no encontró señales de malware en lo que está corriendo ahora.</small></div>';
      box.innerHTML = html;
      return;
    }
    html += '<div id="proc-table"></div>';
    box.innerHTML = html;
    MS.table($('#proc-table'), rows, [
      { key: 'score', label: 'RIESGO', render: p => `${MS.badge(LEVEL[p.level], p.level)} <span class="muted small">${p.score}</span>` },
      { key: 'name', label: 'PROCESO', render: p => `<div class="name">${esc(p.name)}${p.count > 1 ? ` <span class="muted">×${p.count}</span>` : ''}</div><div class="path">${esc(p.path || (p.no_access ? 'sin acceso a la ruta' : ''))}</div>${p.cmdline && p.level !== 'ok' ? `<div class="cmdline">${esc(p.cmdline)}</div>` : ''}` },
      { key: 'signer', label: 'FIRMA', render: sigCell },
      { key: 'cpu', label: 'CPU', cls: 'num', render: p => MS.fmtPct(p.cpu, 1) },
      { key: 'rss', label: 'RAM', cls: 'num', render: p => fmtBytes(p.rss) },
      { key: 'reasons', label: 'SEÑALES', sortable: false, render: p => (p.reasons.length ? reasonChips(p.reasons) : '<span class="muted">--</span>') },
      { key: 'vt', label: 'VT', sortable: false, cls: 'vt-cell', render: p => vtCell(p.path) },
    ], { sortKey: 'score', rowClass: p => 'lvl-' + p.level });
  }

  // ------------------------------------------------------------ arranque
  function renderPersistence(r) {
    const box = $('#persistence-results');
    if (!r.supported) { box.innerHTML = '<div class="empty">> El análisis de arranque solo funciona en Windows.</div>'; return; }
    const onlySus = $('#pers-sus').checked;
    const rows = r.entries.filter(e => !onlySus || e.level !== 'ok');
    let html = `<div class="summary-row">
      <div><div class="big">${r.startup_programs}</div><div class="lbl">PROGRAMAS AL INICIAR SESIÓN</div></div>
      <div><div class="big" style="color:var(--red)">${r.counts.alto}</div><div class="lbl">RIESGO ALTO</div></div>
      <div><div class="big" style="color:var(--amber)">${r.counts.medio}</div><div class="lbl">MEDIO</div></div>
      <div><div class="big">${r.entries.length}</div><div class="lbl">ENTRADAS</div></div>
    </div>
    <div class="note info">Cada programa que arranca con Windows retrasa el inicio y consume en segundo plano. Desactívalos en Administrador de tareas → Aplicaciones de arranque.</div>`;
    if (!rows.length) {
      html += '<div class="allclear">ARRANQUE LIMPIO<small>No hay entradas sospechosas.</small></div>';
      box.innerHTML = html;
      return;
    }
    html += '<div id="pers-table"></div>';
    box.innerHTML = html;
    MS.table($('#pers-table'), rows, [
      { key: 'score', label: 'RIESGO', render: e => `${MS.badge(LEVEL[e.level], e.level)} <span class="muted small">${e.score}</span>` },
      { key: 'name', label: 'NOMBRE', render: e => `<div class="name">${esc(e.name)}</div><div class="path">${esc(e.source)}</div>` },
      { key: 'command', label: 'COMANDO', sortable: false, render: e => `<div class="cmdline">${esc(e.command)}</div>` },
      { key: 'signer', label: 'FIRMA', render: sigCell },
      { key: 'enabled', label: 'ESTADO', render: e => MS.badge(e.enabled ? 'activo' : 'desactivado', e.enabled ? 'ok' : 'dim') },
      { key: 'reasons', label: 'SEÑALES', sortable: false, render: e => (e.reasons.length ? reasonChips(e.reasons) : '<span class="muted">--</span>') },
      { key: 'vt', label: 'VT', sortable: false, cls: 'vt-cell', render: e => vtCell(e.path) },
    ], { sortKey: 'score', rowClass: e => 'lvl-' + e.level });
  }

  function rerender() {
    const r = MS.state.results;
    if (r.processes) renderProcesses(r.processes);
    if (r.persistence) renderPersistence(r.persistence);
    renderVtBanner();
  }

  // ------------------------------------------------------------ init
  MS.initSecurity = function () {
    MS.on('result:defender_status', renderDefender);
    MS.on('result:defender_scan', renderDefender);
    MS.on('result:processes', () => rerender());
    MS.on('result:persistence', () => rerender());
    MS.on('config', renderVtBanner);
    $('#proc-all').addEventListener('change', rerender);
    $('#pers-sus').addEventListener('change', rerender);
    document.addEventListener('click', ev => {
      const b = ev.target.closest('[data-vt]');
      if (b) vtLookup([b.dataset.vt]);
    });
  };
})();
