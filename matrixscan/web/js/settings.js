/* Vista CONFIG. */
(function () {
  'use strict';
  const { $, esc } = MS;
  const lines = v => v.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  function fill(cfg) {
    $('#cfg-vt').value = '';
    $('#cfg-vt-hint').textContent = cfg.has_vt_key ? `(guardada: ${cfg.vt_key_hint})` : '(sin configurar)';
    $('#cfg-roots').value = cfg.scan_roots.join('\n');
    $('#cfg-exclude').value = cfg.exclude_paths.join('\n');
    $('#cfg-large').value = cfg.large_min_mb;
    $('#cfg-days').value = cfg.unused_days;
    $('#cfg-dup').value = cfg.dup_min_mb;
    $('#cfg-appdata').checked = cfg.dup_skip_appdata;
  }

  function renderDrives(sys) {
    const box = $('#cfg-drives');
    box.innerHTML = '<span class="muted small">añadir:</span> ' + sys.disks.map(d => `<button type="button" class="chip" data-drive="${esc(d.mount)}">+ ${esc(d.mount)}</button>`).join('');
    box.querySelectorAll('[data-drive]').forEach(b => b.addEventListener('click', () => {
      const ta = $('#cfg-roots');
      const cur = lines(ta.value);
      if (!cur.includes(b.dataset.drive)) ta.value = cur.concat(b.dataset.drive).join('\n');
    }));
  }

  async function save(updates, msg) {
    try {
      MS.state.config = await MS.api('/api/config', { method: 'POST', body: updates });
      fill(MS.state.config);
      MS.emit('config', MS.state.config);
      MS.toast(msg || 'Configuración guardada.');
    } catch (e) { MS.toast(e.message, 'err'); }
  }

  MS.initSettings = function () {
    MS.on('config', fill);
    MS.on('system', renderDrives);
    $('#settings-form').addEventListener('submit', ev => {
      ev.preventDefault();
      const updates = {
        scan_roots: lines($('#cfg-roots').value),
        exclude_paths: lines($('#cfg-exclude').value),
        large_min_mb: Number($('#cfg-large').value),
        unused_days: Number($('#cfg-days').value),
        dup_min_mb: Number($('#cfg-dup').value),
        dup_skip_appdata: $('#cfg-appdata').checked,
      };
      const key = $('#cfg-vt').value.trim();
      if (key) updates.vt_api_key = key;
      save(updates);
    });
    $('#cfg-vt-clear').addEventListener('click', () => save({ vt_api_key: '' }, 'API key eliminada.'));
  };
})();
