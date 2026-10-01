"""Verificación de firma digital (Authenticode) de ejecutables en Windows."""
from __future__ import annotations

import os
import re
import tempfile
import threading

from ..util import IS_WINDOWS, as_list, powershell_json, ps_quote

_cache: dict[tuple[str, float, int], dict] = {}
_lock = threading.Lock()

_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = foreach ($p in (Get-Content -LiteralPath {listfile} -Encoding UTF8)) {
  if (-not $p) { continue }
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $subj = ''
  if ($s -and $s.SignerCertificate) { $subj = $s.SignerCertificate.Subject }
  [pscustomobject]@{ p = $p; s = $(if ($s) { [string]$s.Status } else { 'UnknownError' }); c = $subj }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def signer_name(subject: str) -> str:
    """Extrae un nombre legible del sujeto del certificado (O= o CN=)."""
    for field in ("O", "CN"):
        m = re.search(rf'(?:^|,\s*){field}=("([^"]+)"|[^,]+)', subject or "")
        if m:
            return (m.group(2) or m.group(1)).strip()
    return ""


def _key(path: str) -> tuple[str, float, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return os.path.normcase(path), st.st_mtime, st.st_size


def check(paths: list[str]) -> dict[str, dict]:
    """Devuelve {ruta_normalizada: {'status': 'Valid'|'NotSigned'|..., 'signer': str}}."""
    result: dict[str, dict] = {}
    if not IS_WINDOWS:
        return result
    pending: list[str] = []
    for p in dict.fromkeys(paths):
        k = _key(p)
        if k is None:
            continue
        with _lock:
            cached = _cache.get(k)
        if cached:
            result[k[0]] = cached
        else:
            pending.append(p)
    for start in range(0, len(pending), 150):
        batch = pending[start:start + 150]
        fd, listfile = tempfile.mkstemp(suffix=".txt", prefix="msig_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8-sig") as fh:
                fh.write("\n".join(batch))
            data = powershell_json(_SCRIPT.replace("{listfile}", ps_quote(listfile)), timeout=180)
        finally:
            try:
                os.remove(listfile)
            except OSError:
                pass
        for row in as_list(data):
            if not isinstance(row, dict) or not row.get("p"):
                continue
            info = {"status": row.get("s") or "UnknownError", "signer": signer_name(row.get("c") or "")}
            k = _key(row["p"])
            if k:
                with _lock:
                    _cache[k] = info
                result[k[0]] = info
    return result
