"""Utilidades compartidas: recorrido de disco, PowerShell, formatos."""
from __future__ import annotations

import base64
import heapq
import json
import os
import stat
import subprocess
import sys
from typing import Iterable, Iterator

IS_WINDOWS = sys.platform == "win32"
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
# Archivos de OneDrive/iCloud solo en la nube: leerlos dispararía su descarga
FILE_ATTRIBUTE_CLOUD = 0x1000 | 0x40000 | 0x400000  # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS
CREATE_NO_WINDOW = 0x08000000


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def norm(path: str) -> str:
    """Ruta normalizada para comparar (minúsculas en Windows)."""
    p = os.path.normpath(path)
    return os.path.normcase(p)


def unique_roots(roots: Iterable[str]) -> list[str]:
    """Quita raíces repetidas o contenidas en otra (evita contar un archivo dos veces)."""
    cleaned = []
    for r in roots:
        if r and os.path.isdir(r):
            cleaned.append(os.path.abspath(r))
    cleaned.sort(key=lambda p: len(norm(p)))
    out: list[str] = []
    for r in cleaned:
        nr = norm(r)
        if any(nr == norm(o) or nr.startswith(norm(o).rstrip("\\/") + os.sep) for o in out):
            continue
        out.append(r)
    return out


def _is_link_or_junction(entry: os.DirEntry) -> bool:
    """Symlinks, junctions y marcadores de posición en la nube: se omiten (evita bucles y descargas)."""
    try:
        if entry.is_symlink():
            return True
        if IS_WINDOWS:
            st = entry.stat(follow_symlinks=False)
            return bool(getattr(st, "st_file_attributes", 0) & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_CLOUD))
    except OSError:
        return True
    return False


class WalkStats:
    def __init__(self) -> None:
        self.files = 0
        self.bytes = 0
        self.denied = 0


def iter_files(
    roots: Iterable[str],
    excluded: Iterable[str] = (),
    excluded_names: Iterable[str] = (),
    check=None,
    stats: WalkStats | None = None,
) -> Iterator[tuple[str, os.stat_result]]:
    """Recorre archivos sin seguir symlinks ni junctions.

    excluded: rutas absolutas a omitir. excluded_names: nombres de carpeta a omitir.
    check: callable que se invoca periódicamente (para cancelar).
    """
    excl = {norm(p) for p in excluded}
    excl_names = {n.lower() for n in excluded_names}
    stats = stats or WalkStats()
    stack = [r for r in roots if os.path.isdir(r)]
    while stack:
        current = stack.pop()
        if check:
            check()
        try:
            it = os.scandir(current)
        except OSError:
            stats.denied += 1
            continue
        with it:
            for entry in it:
                try:
                    if _is_link_or_junction(entry):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name.lower() in excl_names or norm(entry.path) in excl:
                            continue
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        stats.files += 1
                        stats.bytes += st.st_size
                        yield entry.path, st
                except OSError:
                    stats.denied += 1


def dir_summary(path: str, check=None, top_n: int = 8, older_than: float | None = None,
                extensions: tuple[str, ...] = ()) -> dict:
    """Tamaño total, número de archivos y los más grandes de una carpeta o archivo."""
    stats = WalkStats()
    top: list[tuple[int, str]] = []
    total = 0
    count = 0

    def consider(p: str, st: os.stat_result) -> None:
        nonlocal total, count
        if older_than is not None and st.st_mtime > older_than:
            return
        if extensions and not p.lower().endswith(extensions):
            return
        total += st.st_size
        count += 1
        if top_n <= 0:
            return
        if len(top) < top_n:
            heapq.heappush(top, (st.st_size, p))
        elif st.st_size > top[0][0]:
            heapq.heapreplace(top, (st.st_size, p))

    if os.path.isfile(path):
        try:
            consider(path, os.stat(path))
        except OSError:
            stats.denied += 1
    else:
        for p, st in iter_files([path], check=check, stats=stats):
            consider(p, st)
    return {
        "size": total,
        "files": count,
        "denied": stats.denied,
        "top": [{"path": p, "size": s} for s, p in sorted(top, reverse=True)],
    }


def is_regular_file_stat(st: os.stat_result) -> bool:
    return stat.S_ISREG(st.st_mode)


# ---------------------------------------------------------------- PowerShell

def run_powershell(script: str, timeout: float = 60) -> tuple[int, str, str]:
    """Ejecuta un script de PowerShell sin ventana y con salida UTF-8."""
    if not IS_WINDOWS:
        return 1, "", "PowerShell solo está disponible en Windows"
    prefix = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n$ProgressPreference = 'SilentlyContinue'\n"
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-EncodedCommand", encoded]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)
    out = proc.stdout.decode("utf-8", errors="replace").lstrip("﻿")
    err = proc.stderr.decode("utf-8", errors="replace")
    return proc.returncode, out, err


def powershell_json(script: str, timeout: float = 60):
    """Ejecuta PowerShell y parsea la salida JSON. Devuelve None si falla."""
    _, out, _ = run_powershell(script, timeout)
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def as_list(value) -> list:
    """PowerShell serializa listas de un elemento como objeto suelto."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ps_quote(value: str) -> str:
    """Literal de cadena seguro para PowerShell (comillas simples)."""
    return "'" + value.replace("'", "''") + "'"
