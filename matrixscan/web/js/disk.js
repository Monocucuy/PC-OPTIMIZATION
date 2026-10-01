/* Vista DISCO: basura, archivos grandes, duplicados y programas. */
(function () {
  'use strict';
  const { $, $$, esc, fmtBytes, fmtNum } = MS;

  // ------------------------------------------------------------ basura
  function renderJunk(r) {
    const box = $('#junk-results');
    if (!r.categories.length) { box.innerHTML = '<div class="allclear">DISCO LIMPIO<small>No se encontró basura relevante.</small></div>'; return; }
    const max = Math.max(...r.categories.map(c => c.size), 1);
    box.innerHTML = `
      <div class="summary-row">
        <div><div class="big" id="junk-total">0 B</div><div class="lbl">BASURA TOTAL</div></div>
        <div><div class="big">${fmtBytes(r.safe_total)}</div><div class="lbl">SEGURO DE LIMPIAR</div></div>
        <div><div class="big">${r.categories.length}</div><div class="lbl">CATEGORÍAS</div></div>
      </div>
      ${r.partial ? '<div class="note">Algunas carpetas no se pudieron leer por permisos. Ejecuta MatrixScan como administrador para medir todo.</div>' : ''}
      ${r.categories.map(c => `
        <details class="cat">
          <summary>
            ${MS.badge(c.risk)}
            <span class="cat-name">${esc(c.name)}</span>
            ${MS.meter(c.size / max * 100, c.risk === 'revisar' ? 'warn' : '')}
            <span class="cat-size">${fmtBytes(c.size)}</span>
            <span class="cat-files">${fmtNum(c.files)} ${c.id === 'recycle_bin' ? 'elementos' : 'archivos'}</span>
          </summary>
          <div class="cat-body">
            <p class="muted">${esc(c.description)}</p>
            <p class="how">${esc(c.how_to_clean)}</p>
            ${c.paths.length ? `<ul class="filelist">${c.paths.map(p => `<li><span class="path">${esc(p)}</span>${MS.openBtn(p)}</li>`).join('')}</ul>` : ''}
            ${c.top.length ? `<p class="muted small" style="margin-top:12px">ARCHIVOS MÁS PESADOS:</p>
              <ul class="filelist">${c.top.map(f => `<li><span class="path">${esc(f.path)}</span><span class="sz">${fmtBytes(f.size)}</span>${MS.openBtn(f.path)}</li>`).join('')}</ul>` : ''}
            ${c.denied ? `<div class="note">${c.denied} carpeta(s) sin permiso de lectura: el tamaño real puede ser mayor.</div>` : ''}
          </div>
        </details>`).join('')}`;
    MS.countUp($('#junk-total'), r.total, v => fmtBytes(v));
    requestAnimationFrame(() => $$('.meter i', box).forEach(i => { const w = i.style.width; i.style.width = '0'; requestAnimationFrame(() => (i.style.width = w)); }));
  }

  // ------------------------------------------------------------ grandes
  function renderLargeCriteria() {
    const c = MS.state.config;
    if (!c) return;
    $('#large-criteria').textContent = `Más de ${c.large_min_mb} MB y sin abrir hace más de ${c.unused_days} días · en: ${c.scan_roots.join(', ')} (cámbialo en CONFIG)`;
  }

  function renderLarge(r) {
    const box = $('#large-results');
    if (!r.files.length) {
      box.innerHTML = `<div class="allclear">NADA QUE REPORTAR<small>${fmtNum(r.scanned)} archivos revisados: ninguno supera ${r.min_mb || '?'} MB sin usarse en ${r.days || '?'} días.</small></div>`;
      return;
    }
    box.innerHTML = `
      <div class="summary-row">
        <div><div class="big">${fmtBytes(r.total)}</div><div class="lbl">OCUPADO POR ARCHIVOS SIN USO</div></div>
        <div><div class="big">${fmtNum(r.count)}</div><div class="lbl">ARCHIVOS</div></div>
        <div><div class="big">${fmtNum(r.scanned)}</div><div class="lbl">REVISADOS</div></div>
      </div>
      <div class="note ${r.tracking && r.tracking.enabled ? 'info' : ''}">${esc(r.tracking ? r.tracking.note : '')}</div>
      <div class="chips" style="margin-bottom:12px">${r.by_kind.map(([k, s]) => `<span class="chip">${esc(k)} · ${fmtBytes(s)}</span>`).join('')}</div>
      <div id="large-table"></div>`;
    const max = Math.max(...r.files.map(f => f.size), 1);
    MS.table($('#large-table'), r.files, [
      { key: 'path', label: 'ARCHIVO', render: f => `<div class="name">${esc(f.path.split(/[\\/]/).pop())}</div><div class="path">${esc(f.path)}</div>` },
      { key: 'kind', label: 'TIPO', render: f => `<span class="chip">${esc(f.kind)}</span>` },
      { key: 'size', label: 'TAMAÑO', cls: 'num', render: f => fmtBytes(f.size) },
      { key: 'bar', label: '', sortable: false, cls: 'bar-cell', render: f => MS.meter(f.size / max * 100) },
      { key: 'days_unused', label: 'SIN USAR', cls: 'num', render: f => MS.fmtDays(f.days_unused) },
      { key: 'open', label: '', sortable: false, render: f => MS.openBtn(f.path) },
    ], { sortKey: 'size' });
  }

  // ------------------------------------------------------------ duplicados
  function renderDuplicates(r) {
    const box = $('#duplicates-results');
    if (!r.groups.length) {
      box.innerHTML = `<div class="allclear">SIN DUPLICADOS<small>${fmtNum(r.scanned)} archivos revisados.</small></div>`;
      return;
    }
    box.innerHTML = `
      <div class="summary-row">
        <div><div class="big">${fmtBytes(r.wasted)}</div><div class="lbl">RECUPERABLE (COPIAS SOBRANTES)</div></div>
        <div><div class="big">${fmtNum(r.group_count)}</div><div class="lbl">GRUPOS</div></div>
        <div><div class="big">${fmtNum(r.scanned)}</div><div class="lbl">REVISADOS</div></div>
      </div>
      <div class="note info">Cada grupo tiene contenido idéntico byte a byte. Conserva una copia y borra las demás a mano.</div>
      ${r.groups.map(g => `
        <details class="cat">
          <summary>
            ${MS.badge('×' + g.count, 'dim')}
            <span class="cat-name">${esc(g.paths[0].split(/[\\/]/).pop())}</span>
            <span class="muted small">#${esc(g.hash)}</span>
            <span class="cat-size">${fmtBytes(g.wasted)}</span>
            <span class="cat-files">${fmtBytes(g.size)} c/u</span>
          </summary>
          <div class="cat-body"><ul class="filelist">${g.paths.map(p => `<li><span class="path">${esc(p)}</span>${MS.openBtn(p)}</li>`).join('')}</ul></div>
        </details>`).join('')}
      ${r.group_count > r.groups.length ? `<p class="muted small">Mostrando los ${r.groups.length} grupos con más espacio desperdiciado.</p>` : ''}`;
  }

  // ------------------------------------------------------------ programas
  const STATUS = { componente: 'COMPONENTE', en_uso: 'EN USO', poco_uso: 'POCO USO', sin_uso: 'SIN USO', sin_registro: 'SIN REGISTRO', desconocido: 'DESCONOCIDO' };
  let progFilter = 'all', progQuery = '';

  function renderPrograms(r) {
    const box = $('#programs-results');
    if (!r.supported) { box.innerHTML = '<div class="empty">> El inventario de programas solo funciona en Windows.</div>'; return; }
    const counts = {};
    r.programs.forEach(p => (counts[p.status] = (counts[p.status] || 0) + 1));
    box.innerHTML = `
      <div class="summary-row">
        <div><div class="big">${fmtBytes(r.unused_size)}</div><div class="lbl">EN PROGRAMAS SIN USO</div></div>
        <div><div class="big">${r.unused_count}</div><div class="lbl">SIN USO / SIN REGISTRO</div></div>
        <div><div class="big">${r.programs.length}</div><div class="lbl">INSTALADOS · ${fmtBytes(r.total_size)}</div></div>
      </div>
      ${r.prefetch_available ? '' : '<div class="note">Sin acceso a Prefetch: el último uso solo se conoce para programas abiertos desde el menú Inicio o el Explorador. Ejecuta como administrador para mayor precisión.</div>'}
      <div class="note info">Para desinstalar: Configuración → Aplicaciones → Aplicaciones instaladas. "Sin registro" = Windows no tiene constancia de que lo hayas abierto recientemente. <b>Componente</b> = runtime, driver o SDK: no se abren, así que no cuentan como "sin uso".</div>
      <div class="filters">
        <button class="chip ${progFilter === 'all' ? 'on' : ''}" data-pf="all">TODOS ${r.programs.length}</button>
        ${Object.keys(STATUS).filter(s => counts[s]).map(s => `<button class="chip ${progFilter === s ? 'on' : ''}" data-pf="${s}">${STATUS[s]} ${counts[s]}</button>`).join('')}
        <input type="search" id="prog-q" placeholder="buscar…" value="${esc(progQuery)}">
      </div>
      <div id="prog-table"></div>`;
    $$('[data-pf]', box).forEach(b => b.addEventListener('click', () => { progFilter = b.dataset.pf; renderPrograms(r); }));
    $('#prog-q', box).addEventListener('input', e => { progQuery = e.target.value; drawProgTable(r); });
    drawProgTable(r);
  }

  function drawProgTable(r) {
    const q = progQuery.trim().toLowerCase();
    const rows = r.programs.filter(p => (progFilter === 'all' || p.status === progFilter) &&
      (!q || p.name.toLowerCase().includes(q) || p.publisher.toLowerCase().includes(q)));
    const max = Math.max(...r.programs.map(p => p.size), 1);
    MS.table($('#prog-table'), rows, [
      { key: 'name', label: 'PROGRAMA', render: p => `<div class="name">${esc(p.name)}</div><div class="path">${esc(p.publisher)}${p.version ? ' · v' + esc(p.version) : ''}</div>` },
      { key: 'size', label: 'TAMAÑO', cls: 'num', render: p => (p.size ? fmtBytes(p.size) : '<span class="muted">?</span>') },
      { key: 'bar', label: '', sortable: false, cls: 'bar-cell', render: p => MS.meter(p.size / max * 100) },
      { key: 'installed', label: 'INSTALADO', render: p => esc(p.installed || '--') },
      { key: 'last_used', label: 'ÚLTIMO USO', render: p => (p.last_used ? `${MS.fmtAgo(p.last_used)}<div class="path">${esc(p.usage_source)}</div>` : '<span class="muted">--</span>') },
      { key: 'status', label: 'ESTADO', render: p => MS.badge(STATUS[p.status], p.status), sort: p => ['componente', 'en_uso', 'poco_uso', 'desconocido', 'sin_registro', 'sin_uso'].indexOf(p.status) },
      { key: 'open', label: '', sortable: false, render: p => MS.openBtn(p.location) },
    ], { sortKey: 'size' });
  }

  // ------------------------------------------------------------ init
  MS.initDisk = function () {
    $$('#view-disk .tabs button').forEach(b => b.addEventListener('click', () => {
      $$('#view-disk .tabs button').forEach(x => x.classList.toggle('active', x === b));
      $$('#view-disk .tabpane').forEach(p => p.classList.toggle('active', p.dataset.pane === b.dataset.tab));
    }));
    MS.on('result:junk', renderJunk);
    MS.on('result:large', renderLarge);
    MS.on('result:duplicates', renderDuplicates);
    MS.on('result:programs', renderPrograms);
    MS.on('config', renderLargeCriteria);
    MS.on('results', () => {
      const r = MS.state.results;
      const cnt = { junk: r.junk && fmtBytes(r.junk.total), large: r.large && fmtBytes(r.large.total),
        duplicates: r.duplicates && fmtBytes(r.duplicates.wasted), programs: r.programs && r.programs.supported && r.programs.unused_count };
      $$('#view-disk .tabs button').forEach(b => {
        const v = cnt[b.dataset.tab];
        let span = $('.cnt', b);
        if (v == null || v === false) return;
        if (!span) { span = document.createElement('span'); span.className = 'cnt'; b.appendChild(span); }
        span.textContent = v;
      });
    });
  };
})();
