"""Consulta de hashes en VirusTotal (API pública v3).

Solo se envía el SHA-256 del archivo, nunca el archivo. La API gratuita permite
4 consultas por minuto y 500 por día, así que las consultas se espacian 15 s.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request

from .. import config
from ..jobs import Job, JobError

API = "https://www.virustotal.com/api/v3/files/"
MIN_INTERVAL = 15.5
CACHE_TTL = 7 * 86400
MAX_PER_JOB = 20

_lock = threading.Lock()
_last_request = 0.0


def sha256_of(path: str, check=None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            if check:
                check()
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _cache_path():
    return config.config_dir() / "vt_cache.json"


def _load_cache() -> dict:
    try:
        with open(_cache_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict) -> None:
    now = time.time()
    cache = {k: v for k, v in cache.items() if now - v.get("checked", 0) < CACHE_TTL}
    try:
        with open(_cache_path(), "w", encoding="utf-8") as fh:
            json.dump(cache, fh)
    except OSError:
        pass


def parse_report(payload: dict) -> dict:
    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    if malicious >= 5:
        verdict = "malicioso"
    elif malicious >= 1 or suspicious >= 3:
        verdict = "sospechoso"
    else:
        verdict = "limpio"
    return {"found": True, "malicious": malicious, "suspicious": suspicious, "engines": total,
            "verdict": verdict, "label": label, "name": attrs.get("meaningful_name") or "",
            "reputation": attrs.get("reputation", 0)}


def _request(sha: str, api_key: str, job: Job) -> dict:
    global _last_request
    with _lock:
        wait = _last_request + MIN_INTERVAL - time.monotonic()
        if wait > 0:
            job.set_progress(job.progress, f"Límite de la API gratuita: esperando {wait:.0f} s")
            job.sleep(wait)
        _last_request = time.monotonic()
    req = urllib.request.Request(API + sha, headers={"x-apikey": api_key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return parse_report(json.loads(resp.read().decode("utf-8")))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"found": False, "verdict": "desconocido", "malicious": 0, "engines": 0}
        if exc.code in (401, 403):
            raise JobError("VirusTotal rechazó la API key. Revísala en CONFIG.") from exc
        if exc.code == 429:
            raise JobError("Se agotó la cuota gratuita de VirusTotal (4/min, 500/día). Intenta más tarde.") from exc
        raise JobError(f"VirusTotal respondió HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise JobError(f"No hay conexión con VirusTotal: {exc.reason}") from exc


def lookup(job: Job, paths: list[str]) -> dict:
    api_key = config.load().get("vt_api_key") or ""
    if not api_key:
        raise JobError("Falta la API key de VirusTotal. Créala gratis en virustotal.com y pégala en CONFIG.")
    paths = list(dict.fromkeys(p for p in paths if p))[:MAX_PER_JOB]
    cache = _load_cache()
    results: dict[str, dict] = {}
    job.log(f"> Consultando {len(paths)} archivo(s) en VirusTotal (solo se envía el hash SHA-256)")
    try:
        for i, path in enumerate(paths):
            job.check()
            job.set_progress(i / max(1, len(paths)), f"Calculando hash: {path}")
            try:
                sha = sha256_of(path, job.check)
            except OSError as exc:
                results[path] = {"error": f"No se pudo leer el archivo: {exc.strerror or exc}"}
                job.log(f"  [!!] {path}: no se pudo leer")
                continue
            cached = cache.get(sha)
            if cached and time.time() - cached.get("checked", 0) < CACHE_TTL:
                report = dict(cached, cached=True)
            else:
                job.set_progress(i / max(1, len(paths)), f"Consultando VirusTotal: {path}")
                report = _request(sha, api_key, job)
                report["checked"] = time.time()
                cache[sha] = report
            report["sha256"] = sha
            report["link"] = f"https://www.virustotal.com/gui/file/{sha}"
            results[path] = report
            if report.get("found"):
                job.log(f"  [{report['malicious']:>2}/{report['engines']}] {path} → {report['verdict'].upper()}")
            else:
                job.log(f"  [ ?? ] {path} → VirusTotal no conoce este archivo")
    finally:
        _save_cache(cache)
    return {"results": results}
