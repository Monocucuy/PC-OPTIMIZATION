"""Archivos grandes que no se usan hace tiempo. Solo reporta."""
from __future__ import annotations

import heapq
import os
import time

from ..jobs import Job
from ..util import IS_WINDOWS, WalkStats, human_size, iter_files, unique_roots
from ..winapi import last_access_tracking

KINDS = {
    "Video": (".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".ts"),
    "Imagen de disco": (".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow2"),
    "Comprimido": (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"),
    "Instalador": (".exe", ".msi", ".msix", ".appx"),
    "Mod / juego": (".scs", ".pak", ".bsa", ".vpk", ".wad"),
    "Audio": (".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"),
    "3D / diseño": (".blend", ".blend1", ".fbx", ".obj", ".psd", ".max"),
    "Respaldo": (".bak", ".old", ".backup"),
    "Documento": (".pdf", ".docx", ".xlsx", ".pptx", ".epub"),
    "Base de datos": (".db", ".sqlite", ".mdf", ".ldf"),
}
_SKIP_FILES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log", "dumpstack.log.tmp"}
_SKIP_DIR_NAMES = ["$Recycle.Bin", "System Volume Information", "$WinREAgent", "Recovery", "Config.Msi",
                   "node_modules", ".git"]


def kind_of(path: str) -> str:
    low = path.lower()
    for kind, exts in KINDS.items():
        if low.endswith(exts):
            return kind
    return "Otro"


def system_exclusions() -> list[str]:
    if not IS_WINDOWS:
        return ["/proc", "/sys", "/dev", "/run", "/snap", "/usr", "/var/lib", "/boot"]
    out = []
    for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        val = os.environ.get(var)
        if val:
            out.append(val)
    return out


def scan(job: Job, roots: list[str], min_mb: float, days: int, exclude: list[str] | None = None) -> dict:
    min_bytes = int(min_mb * 1024 * 1024)
    cutoff = time.time() - days * 86400
    roots = unique_roots(roots)
    if not roots:
        return {"files": [], "total": 0, "scanned": 0, "roots": [], "tracking": last_access_tracking()}
    job.log(f"> Buscando archivos de más de {human_size(min_bytes)} sin usar en {days} días")
    for r in roots:
        job.log(f"  raíz: {r}")
    stats = WalkStats()
    heap: list[tuple[int, str, float]] = []
    matches = 0
    match_bytes = 0
    last_report = 0.0
    excluded = system_exclusions() + list(exclude or [])

    for path, st in iter_files(roots, excluded=excluded, excluded_names=_SKIP_DIR_NAMES,
                               check=job.check, stats=stats):
        now = time.monotonic()
        if now - last_report > 0.4:
            last_report = now
            job.set_progress(None, f"{stats.files:,} archivos revisados · {matches} candidatos")
        if st.st_size < min_bytes or os.path.basename(path).lower() in _SKIP_FILES:
            continue
        last_used = max(st.st_atime, st.st_mtime)
        if last_used > cutoff:
            continue
        matches += 1
        match_bytes += st.st_size
        item = (st.st_size, path, last_used)
        if len(heap) < 500:
            heapq.heappush(heap, item)
        elif item > heap[0]:
            heapq.heapreplace(heap, item)

    files = [{
        "path": p, "size": s, "last_used": lu, "days_unused": int((time.time() - lu) // 86400),
        "kind": kind_of(p),
    } for s, p, lu in sorted(heap, reverse=True)]
    by_kind: dict[str, int] = {}
    for f in files:
        by_kind[f["kind"]] = by_kind.get(f["kind"], 0) + f["size"]
    job.log(f"> {stats.files:,} archivos revisados. {matches} grandes sin usar ({human_size(match_bytes)}).")
    if stats.denied:
        job.log(f"> {stats.denied} carpetas sin permiso de lectura.")
    return {
        "files": files, "total": match_bytes, "count": matches, "scanned": stats.files,
        "denied": stats.denied, "roots": roots, "min_mb": min_mb, "days": days,
        "by_kind": sorted(by_kind.items(), key=lambda kv: kv[1], reverse=True),
        "tracking": last_access_tracking(),
    }
