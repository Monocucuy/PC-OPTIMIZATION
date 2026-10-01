"""Archivos duplicados por contenido (hash), no por nombre. Solo reporta."""
from __future__ import annotations

import hashlib
import os
import time
from collections import defaultdict

from ..jobs import Job
from ..util import WalkStats, human_size, iter_files, unique_roots
from .large_files import _SKIP_DIR_NAMES, system_exclusions

PARTIAL_BYTES = 64 * 1024
CHUNK = 1024 * 1024


def _partial_hash(path: str, size: int) -> str | None:
    h = hashlib.blake2b(digest_size=16)
    try:
        with open(path, "rb") as fh:
            h.update(fh.read(PARTIAL_BYTES))
            if size > 2 * PARTIAL_BYTES:
                fh.seek(-PARTIAL_BYTES, os.SEEK_END)
                h.update(fh.read(PARTIAL_BYTES))
    except OSError:
        return None
    return h.hexdigest()


def _full_hash(path: str, check, on_bytes) -> str | None:
    h = hashlib.blake2b(digest_size=20)
    try:
        with open(path, "rb") as fh:
            while True:
                check()
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                h.update(chunk)
                on_bytes(len(chunk))
    except OSError:
        return None
    return h.hexdigest()


def scan(job: Job, roots: list[str], min_mb: float, skip_appdata: bool = True,
         exclude: list[str] | None = None) -> dict:
    min_bytes = max(1, int(min_mb * 1024 * 1024))
    roots = unique_roots(roots)
    skip_names = list(_SKIP_DIR_NAMES) + (["AppData"] if skip_appdata else [])
    excluded = system_exclusions() + list(exclude or [])

    # Fase 1: agrupar por tamaño
    job.log(f"> Fase 1/3: agrupando archivos de más de {human_size(min_bytes)} por tamaño")
    stats = WalkStats()
    by_size: dict[int, list[str]] = defaultdict(list)
    last = 0.0
    for path, st in iter_files(roots, excluded=excluded, excluded_names=skip_names, check=job.check, stats=stats):
        if st.st_size >= min_bytes:
            by_size[st.st_size].append(path)
        if time.monotonic() - last > 0.4:
            last = time.monotonic()
            job.set_progress(None, f"Fase 1/3 · {stats.files:,} archivos revisados")
    candidates = {s: ps for s, ps in by_size.items() if len(ps) > 1}
    n_cand = sum(len(ps) for ps in candidates.values())
    job.log(f"  {stats.files:,} archivos revisados, {n_cand} con tamaño repetido")

    # Fase 2: hash parcial (inicio y final del archivo)
    job.log("> Fase 2/3: comparando inicio y final de cada archivo")
    by_partial: dict[tuple[int, str], list[str]] = defaultdict(list)
    done = 0
    for size, paths in candidates.items():
        for p in paths:
            job.check()
            ph = _partial_hash(p, size)
            if ph:
                by_partial[(size, ph)].append(p)
            done += 1
            if done % 50 == 0:
                job.set_progress(0.1 + 0.2 * done / max(1, n_cand), f"Fase 2/3 · {done}/{n_cand}")
    partial_groups = [(s, ps) for (s, _), ps in by_partial.items() if len(ps) > 1]

    # Fase 3: hash completo
    total_bytes = sum(s * len(ps) for s, ps in partial_groups) or 1
    hashed = 0
    job.log(f"> Fase 3/3: verificando contenido completo ({human_size(total_bytes)})")

    def on_bytes(n: int) -> None:
        nonlocal hashed
        hashed += n
        job.set_progress(0.3 + 0.7 * hashed / total_bytes, f"Fase 3/3 · {human_size(hashed)} / {human_size(total_bytes)}")

    groups = []
    for size, paths in partial_groups:
        by_full: dict[str, list[str]] = defaultdict(list)
        for p in paths:
            fh = _full_hash(p, job.check, on_bytes)
            if fh:
                by_full[fh].append(p)
        for digest, same in by_full.items():
            if len(same) > 1:
                groups.append({"hash": digest[:12], "size": size, "count": len(same),
                               "wasted": size * (len(same) - 1), "paths": sorted(same)})

    groups.sort(key=lambda g: g["wasted"], reverse=True)
    wasted = sum(g["wasted"] for g in groups)
    job.log(f"> {len(groups)} grupos de duplicados. Espacio recuperable: {human_size(wasted)}")
    return {"groups": groups[:300], "group_count": len(groups), "wasted": wasted,
            "scanned": stats.files, "roots": roots, "min_mb": min_mb}
