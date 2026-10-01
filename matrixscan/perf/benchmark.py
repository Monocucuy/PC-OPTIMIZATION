"""Benchmark antes/después: mide el rendimiento con los procesos en segundo plano activos y
con los seleccionados en pausa, para cuantificar cuánto te quitan.

Pausar = suspender temporalmente (como 'congelar'). Se reanudan siempre al terminar, al cancelar,
al cerrar MatrixScan o, como último recurso, a los 120 s por un temporizador de seguridad.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import statistics
import tempfile
import threading
import time

import psutil

from .. import config
from ..jobs import Job, JobError
from ..security.processes import own_tree
from ..winapi import install_console_close_handler
from .monitor import BROWSERS, MONITOR, PROTECTED

SAFETY_RESUME_S = 120
_suspended: dict[int, psutil.Process] = {}
_susp_lock = threading.Lock()
_watchdog: threading.Timer | None = None

TESTS = {
    "cpu_multi": {"label": "CPU multinúcleo", "unit": "MB/s", "higher_better": True, "weight": 0.35},
    "cpu_single": {"label": "CPU un núcleo", "unit": "MB/s", "higher_better": True, "weight": 0.2},
    "memory": {"label": "Memoria RAM", "unit": "GB/s", "higher_better": True, "weight": 0.1},
    "disk_write": {"label": "Disco: escritura", "unit": "MB/s", "higher_better": True, "weight": 0.2},
    "disk_latency": {"label": "Disco: latencia", "unit": "ms", "higher_better": False, "weight": 0.15},
}


# ------------------------------------------------------------------ pruebas

def _hash_worker(buf: bytes, stop: float, counter: list, idx: int) -> None:
    n = 0
    while time.perf_counter() < stop:
        hashlib.sha256(buf).digest()  # hashlib libera el GIL: usa núcleos reales
        n += 1
    counter[idx] = n


def bench_cpu(threads: int, seconds: float) -> float:
    buf = os.urandom(1024 * 1024)
    counter = [0] * threads
    stop = time.perf_counter() + seconds
    workers = [threading.Thread(target=_hash_worker, args=(buf, stop, counter, i)) for i in range(threads)]
    t0 = time.perf_counter()
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    elapsed = time.perf_counter() - t0
    return sum(counter) / elapsed  # MB/s (1 MB por iteración)


def bench_memory(seconds: float) -> float:
    src = bytearray(os.urandom(1024 * 1024)) * 64  # 64 MB
    dst = memoryview(bytearray(len(src)))
    dst[:] = src  # calentamiento: asigna las páginas antes de medir
    copied = 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < seconds:
        dst[:] = src
        copied += len(src)
    return copied / (time.perf_counter() - t0) / 1024 ** 3


def bench_disk_write(folder: str, size_mb: int = 128) -> float:
    chunk = os.urandom(1024 * 1024)
    fd, path = tempfile.mkstemp(prefix="msbench_", dir=folder)
    try:
        t0 = time.perf_counter()
        with os.fdopen(fd, "wb", buffering=0) as fh:
            for _ in range(size_mb):
                fh.write(chunk)
            os.fsync(fh.fileno())
        return size_mb / (time.perf_counter() - t0)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def bench_disk_latency(folder: str, ops: int = 100) -> float:
    block = os.urandom(4096)
    fd, path = tempfile.mkstemp(prefix="msbench_", dir=folder)
    try:
        times = []
        with os.fdopen(fd, "wb", buffering=0) as fh:
            for _ in range(ops):
                t0 = time.perf_counter()
                fh.write(block)
                os.fsync(fh.fileno())
                times.append(time.perf_counter() - t0)
        return statistics.median(times) * 1000
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def run_suite(job: Job, label: str, base_progress: float, span: float, quick: bool = False) -> dict:
    """Ejecuta todas las pruebas varias veces y devuelve {test: {value, runs, spread}}."""
    reps = 2 if quick else 3
    cpu_s = 0.8 if quick else 2.0
    folder = tempfile.gettempdir()
    threads = max(1, psutil.cpu_count() or 1)
    plan = [
        ("cpu_multi", lambda: bench_cpu(threads, cpu_s)),
        ("cpu_single", lambda: bench_cpu(1, cpu_s * 0.75)),
        ("memory", lambda: bench_memory(cpu_s * 0.5)),
        ("disk_write", lambda: bench_disk_write(folder, 32 if quick else 128)),
        ("disk_latency", lambda: bench_disk_latency(folder, 30 if quick else 100)),
    ]
    out = {}
    steps = len(plan) * reps
    step = 0
    for key, fn in plan:
        runs = []
        for _ in range(reps):
            job.check()
            job.set_progress(base_progress + span * step / steps, f"{label} · {TESTS[key]['label']}")
            runs.append(fn())
            step += 1
        value = statistics.median(runs)
        spread = (max(runs) - min(runs)) / value * 100 if value else 0
        out[key] = {"value": value, "runs": runs, "spread": round(spread, 1)}
        job.log(f"  {TESTS[key]['label']:<18} {value:10.2f} {TESTS[key]['unit']}  (±{spread / 2:.1f}%)")
    return out


def compare(base: dict, paused: dict) -> tuple[list[dict], float]:
    """Diferencia porcentual por prueba y pérdida global ponderada."""
    rows = []
    weighted = 0.0
    for key, meta in TESTS.items():
        b, p = base[key]["value"], paused[key]["value"]
        if not b or not p:
            continue
        # Mejora al pausar = rendimiento que los procesos te estaban quitando
        gain = (p - b) / b * 100 if meta["higher_better"] else (b - p) / b * 100
        noise = max(base[key]["spread"], paused[key]["spread"]) / 2 + 2.0
        significant = abs(gain) > noise
        rows.append({"test": key, "label": meta["label"], "unit": meta["unit"], "base": b, "paused": p,
                     "gain_pct": round(gain, 1), "noise_pct": round(noise, 1), "significant": significant})
        if significant and gain > 0:
            weighted += gain * meta["weight"]
    return rows, round(weighted, 1)


# ------------------------------------------------------------------ pausa segura

def _recovery_path():
    return config.config_dir() / "suspended.json"


def _persist_suspended() -> None:
    """Guarda en disco qué procesos están en pausa por si MatrixScan muere sin reanudarlos."""
    with _susp_lock:
        data = []
        for p in _suspended.values():
            try:
                data.append({"pid": p.pid, "created": p.create_time()})
            except psutil.Error:
                continue
    try:
        if data:
            _recovery_path().write_text(json.dumps(data), encoding="utf-8")
        else:
            _recovery_path().unlink(missing_ok=True)
    except OSError:
        pass


def recover_suspended() -> int:
    """Al arrancar: reanuda procesos que quedaron en pausa si MatrixScan se cerró a la fuerza."""
    path = _recovery_path()
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    resumed = 0
    for e in entries if isinstance(entries, list) else []:
        try:
            p = psutil.Process(int(e["pid"]))
            # create_time evita reanudar un proceso distinto que reutilizó el mismo PID
            if abs(p.create_time() - float(e["created"])) < 1:
                p.resume()
                resumed += 1
        except (psutil.Error, KeyError, TypeError, ValueError):
            continue
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
    return resumed


def resume_all() -> int:
    global _watchdog
    with _susp_lock:
        procs = list(_suspended.values())
        _suspended.clear()
        if _watchdog:
            _watchdog.cancel()
            _watchdog = None
    resumed = 0
    for p in procs:
        try:
            p.resume()
            resumed += 1
        except psutil.Error:
            pass
    _persist_suspended()
    return resumed


atexit.register(resume_all)
install_console_close_handler(resume_all)


def _ui_browser_names(port: int | None) -> set[str]:
    """Nombre del navegador que muestra esta interfaz (pausarlo congelaría la pantalla)."""
    names: set[str] = set()
    if not port:
        return names
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.raddr and conn.raddr.port == port and conn.pid:
                try:
                    names.add(psutil.Process(conn.pid).name().lower())
                except psutil.Error:
                    pass
    except (psutil.Error, OSError):
        pass
    return names


def candidates(port: int | None = None) -> dict:
    """Procesos en segundo plano que más consumen y que se pueden pausar con seguridad."""
    ui = _ui_browser_names(port)
    own = own_tree()
    out = []
    for name, g in MONITOR.groups_by_name().items():
        if g["cpu_avg"] < 0.3 and g["rss"] < 150 * 1024 ** 2 and g["io"] < 512 * 1024:
            continue
        blocked = ""
        if name in PROTECTED:
            blocked = "Proceso crítico de Windows"
        elif name in ui or (not ui and name in BROWSERS):
            blocked = "Es el navegador que muestra MatrixScan"
        elif any(pid in own for pid in g["pids"]):
            blocked = "Es parte de MatrixScan"
        impact = g["cpu_avg"] * 3 + g["rss"] / 1024 ** 3 * 2 + g["io"] / (5 * 1024 ** 2)
        out.append({
            "name": g["name"], "count": g["count"], "cpu_avg": g["cpu_avg"], "rss": g["rss"], "io": g["io"],
            "foreground": g["foreground"], "service": g["service"], "blocked": blocked,
            "impact": round(impact, 2),
            "suggested": not blocked and not g["foreground"] and (g["cpu_avg"] >= 1 or g["rss"] > 400 * 1024 ** 2),
        })
    out.sort(key=lambda c: c["impact"], reverse=True)
    out = out[:20]
    picked = 0
    for c in out:
        if c["suggested"]:
            picked += 1
            c["suggested"] = picked <= 6
    return {"candidates": out, "ui_browser": sorted(ui)}


def _suspend(names: list[str], job: Job, port: int | None) -> tuple[list[dict], list[str]]:
    global _watchdog
    wanted = {n.lower() for n in names}
    ui = _ui_browser_names(port)
    blocked = PROTECTED | (ui or BROWSERS)
    own = own_tree()
    paused: dict[str, int] = {}
    failed: dict[str, str] = {}
    for p in psutil.process_iter(["name"]):
        name = (p.info.get("name") or "").lower()
        if name not in wanted or p.pid in own:
            continue
        if name in blocked:
            failed[name] = "protegido"
            continue
        try:
            p.suspend()
            with _susp_lock:
                _suspended[p.pid] = p
            _persist_suspended()
            paused[name] = paused.get(name, 0) + 1
        except psutil.AccessDenied:
            failed.setdefault(name, "sin permiso (requiere admin)")
        except psutil.Error:
            continue
    with _susp_lock:
        if _suspended and _watchdog is None:
            _watchdog = threading.Timer(SAFETY_RESUME_S, resume_all)
            _watchdog.daemon = True
            _watchdog.start()
    for name, n in paused.items():
        job.log(f"  [PAUSA] {name} ×{n}")
    for name, why in failed.items():
        job.log(f"  [ -- ] {name}: {why}")
    return ([{"name": n, "instances": c} for n, c in paused.items()],
            [f"{n}: {w}" for n, w in failed.items()])


# ------------------------------------------------------------------ trabajo

def _history_path():
    return config.config_dir() / "benchmarks.json"


def history() -> list[dict]:
    try:
        with open(_history_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save_history(entry: dict) -> None:
    data = history()
    data.append(entry)
    try:
        with open(_history_path(), "w", encoding="utf-8") as fh:
            json.dump(data[-30:], fh)
    except OSError:
        pass


def run(job: Job, names: list[str] | None = None, port: int | None = None, quick: bool = False) -> dict:
    names = [n for n in (names or []) if isinstance(n, str)]
    phases = 2 if names else 1
    impact_now = MONITOR.groups_by_name()
    job.log(f"> BENCHMARK · {'comparativo' if names else 'solo medición base'}")
    job.log(f"> Fase 1/{phases}: con todos los procesos activos")
    base = run_suite(job, f"Fase 1/{phases}", 0.0, 0.48 if names else 1.0, quick)
    result = {"timestamp": time.time(), "baseline": base, "paused": None, "comparison": [],
              "loss_pct": None, "paused_procs": [], "failed": [], "attribution": []}
    if names:
        job.log(f"> Pausando {len(names)} proceso(s) seleccionado(s)...")
        try:
            paused_procs, failed = _suspend(names, job, port)
            result["paused_procs"], result["failed"] = paused_procs, failed
            if not paused_procs:
                raise JobError("No se pudo pausar ningún proceso. Ejecuta MatrixScan como administrador.")
            job.log("> Esperando 3 s a que el sistema se estabilice...")
            job.sleep(3)
            job.log("> Fase 2/2: con los procesos en pausa")
            paused = run_suite(job, "Fase 2/2", 0.52, 0.46, quick)
        finally:
            n = resume_all()
            job.log(f"> {n} procesos reanudados.")
        result["paused"] = paused
        rows, loss = compare(base, paused)
        result["comparison"], result["loss_pct"] = rows, loss
        total_cpu = sum(impact_now.get(p["name"], {}).get("cpu_avg", 0) for p in paused_procs) or 1
        result["attribution"] = sorted([
            {"name": p["name"], "share_pct": round(impact_now.get(p["name"], {}).get("cpu_avg", 0) / total_cpu * 100),
             "cpu_avg": impact_now.get(p["name"], {}).get("cpu_avg", 0),
             "rss": impact_now.get(p["name"], {}).get("rss", 0)} for p in paused_procs
        ], key=lambda a: a["share_pct"], reverse=True)
        job.log(f"> RESULTADO: los procesos pausados te quitan ~{loss}% de rendimiento ponderado.")
        for r in rows:
            mark = "*" if r["significant"] else " "
            job.log(f"  {mark} {r['label']:<18} {r['gain_pct']:+6.1f}%  (margen ±{r['noise_pct']}%)")
    summary = {"timestamp": result["timestamp"], "loss_pct": result["loss_pct"],
               "scores": {k: v["value"] for k, v in base.items()}, "paused": [p["name"] for p in result["paused_procs"]]}
    _save_history(summary)
    result["history"] = history()
    return result
