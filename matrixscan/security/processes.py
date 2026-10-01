"""Análisis heurístico de los procesos en ejecución."""
from __future__ import annotations

import ipaddress
import os

import psutil

from ..jobs import Job
from ..util import IS_WINDOWS
from . import signatures
from .heuristics import assess, level_for

_LEVEL_ORDER = {"alto": 3, "medio": 2, "bajo": 1, "ok": 0}


def own_tree() -> set[int]:
    """PIDs de MatrixScan, sus hijos (PowerShell) y sus padres (consola que lo lanzó)."""
    pids = {os.getpid()}
    try:
        me = psutil.Process()
        pids.update(c.pid for c in me.children(recursive=True))
        pids.update(p.pid for p in me.parents())
    except psutil.Error:
        pass
    return pids


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_unspecified)


def internet_pids() -> set[int]:
    pids: set[int] = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid and conn.status == psutil.CONN_ESTABLISHED and conn.raddr and _is_public(conn.raddr.ip):
                pids.add(conn.pid)
    except (psutil.Error, OSError):
        pass
    return pids


def scan(job: Job) -> dict:
    skip = own_tree()
    job.log("> Enumerando procesos en ejecución...")
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid"]):
        if p.pid in skip or (IS_WINDOWS and p.pid in (0, 4)):
            continue
        procs.append(p)
    job.log(f"  {len(procs)} procesos activos")

    job.set_progress(0.1, "Midiendo consumo de CPU (1 s)")
    for p in procs:
        try:
            p.cpu_percent(None)
        except psutil.Error:
            pass
    job.sleep(1.0)
    ncpu = psutil.cpu_count() or 1
    cpu: dict[int, float] = {}
    rss: dict[int, int] = {}
    for p in procs:
        try:
            cpu[p.pid] = p.cpu_percent(None) / ncpu
            rss[p.pid] = p.memory_info().rss
        except psutil.Error:
            cpu[p.pid] = 0.0

    job.set_progress(0.25, "Revisando conexiones de red")
    net = internet_pids()
    names = {p.pid: (p.info.get("name") or "") for p in procs}

    exes = sorted({p.info["exe"] for p in procs if p.info.get("exe")})
    if IS_WINDOWS:
        job.log(f"> Verificando firma digital de {len(exes)} ejecutables...")
        job.set_progress(0.35, "Verificando firmas digitales")
    sigs = signatures.check(exes)
    job.check()

    windir = os.environ.get("SystemRoot", r"C:\Windows")
    groups: dict[tuple, dict] = {}
    no_access = 0
    job.set_progress(0.8, "Aplicando heurística")
    for p in procs:
        info = p.info
        name = info.get("name") or "?"
        exe = info.get("exe") or ""
        if not exe:
            no_access += 1
        cmd = " ".join(info.get("cmdline") or [])
        sig = sigs.get(os.path.normcase(exe)) if exe else None
        verdict = assess(exe or None, name, cmdline=cmd, signature=sig,
                         parent_name=names.get(info.get("ppid") or -1, ""),
                         cpu_percent=cpu.get(p.pid, 0.0), has_internet=p.pid in net,
                         exists=os.path.exists(exe) if exe else None, windir=windir)
        codes = tuple(sorted(r["text"] for r in verdict["reasons"] if r["code"] != "cpu"))
        key = ((exe or name).lower(), codes)
        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "name": name, "path": exe, "pids": [], "count": 0, "cpu": 0.0, "rss": 0,
                "user": info.get("username") or "", "signer": (sig or {}).get("signer", ""),
                "sig_status": (sig or {}).get("status", "N/A" if not IS_WINDOWS else ("" if not exe else "?")),
                "score": 0, "reasons": [], "cmdline": cmd[:400], "no_access": not exe,
            }
        g["pids"].append(p.pid)
        g["count"] += 1
        g["cpu"] += cpu.get(p.pid, 0.0)
        g["rss"] += rss.get(p.pid, 0)
        if verdict["score"] >= g["score"]:
            g["score"] = verdict["score"]
            g["reasons"] = verdict["reasons"]

    rows = list(groups.values())
    for g in rows:
        g["level"] = level_for(g["score"])
        g["cpu"] = round(g["cpu"], 1)
        g["pids"] = g["pids"][:20]
    rows.sort(key=lambda g: (_LEVEL_ORDER[g["level"]], g["score"], g["cpu"]), reverse=True)
    counts = {lvl: sum(1 for g in rows if g["level"] == lvl) for lvl in _LEVEL_ORDER}
    job.log(f"> Resultado: {counts['alto']} alto · {counts['medio']} medio · {counts['bajo']} bajo")
    if no_access:
        job.log(f"> {no_access} procesos protegidos no se pudieron inspeccionar (normal sin admin).")
    return {"processes": rows, "counts": counts, "total": len(procs), "no_access": no_access,
            "signatures_checked": IS_WINDOWS}
