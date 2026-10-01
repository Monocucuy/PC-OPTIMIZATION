"""Programas instalados, su tamaño y la última vez que se ejecutaron.

Fuentes de 'último uso':
  - Prefetch (C:\\Windows\\Prefetch): Windows guarda un archivo por ejecutable usado. Requiere admin.
  - UserAssist (registro del usuario): programas abiertos desde el Explorador o el menú Inicio.
"""
from __future__ import annotations

import codecs
import os
import re
import struct
import time

from ..jobs import Job
from ..util import IS_WINDOWS, dir_summary
from ..winapi import reg_subkeys, reg_values

UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
USERASSIST = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
FILETIME_EPOCH = 116444736000000000

KNOWN_FOLDERS = {
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "%ProgramFiles%",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "%ProgramFiles(x86)%",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "%SystemRoot%",
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": r"%SystemRoot%\System32",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": r"%SystemRoot%\SysWOW64",
}
_NOT_USAGE = re.compile(r"^(unins\d*|uninstall\w*|uninst|setup|install\w*|update\w*|crashpad_handler|"
                        r"crashreporter|.*helper|vc_redist.*|dxsetup)\.exe$", re.I)
_SKIP_NAME = re.compile(r"^(security update|update for|hotfix|actualización de seguridad)", re.I)


def filetime_to_unix(ft: int) -> float | None:
    if not ft:
        return None
    ts = (ft - FILETIME_EPOCH) / 10_000_000
    return ts if 946684800 < ts < time.time() + 86400 else None


def parse_userassist_value(name: str, data: bytes) -> tuple[str, int, float | None] | None:
    """Decodifica una entrada UserAssist (nombre en ROT13, datos de 72 bytes en Win7+)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 68:
        return None
    path = codecs.decode(name, "rot_13")
    for guid, folder in KNOWN_FOLDERS.items():
        if path.upper().startswith(guid):
            path = folder + path[len(guid):]
            break
    count = struct.unpack_from("<I", data, 4)[0]
    last = filetime_to_unix(struct.unpack_from("<Q", data, 60)[0])
    return path, count, last


def userassist_usage() -> tuple[dict[str, float], dict[str, float]]:
    """Devuelve (exe_en_mayúsculas → último uso, nombre_de_acceso_directo → último uso)."""
    exes: dict[str, float] = {}
    links: dict[str, float] = {}
    if not IS_WINDOWS:
        return exes, links
    import winreg
    for guid in reg_subkeys(winreg.HKEY_CURRENT_USER, USERASSIST):
        for name, data, _ in reg_values(winreg.HKEY_CURRENT_USER, rf"{USERASSIST}\{guid}\Count"):
            parsed = parse_userassist_value(name, data)
            if not parsed or not parsed[2]:
                continue
            path, _, last = parsed
            base = path.replace("/", "\\").rsplit("\\", 1)[-1]
            low = base.lower()
            if low.endswith(".exe"):
                exes[base.upper()] = max(last, exes.get(base.upper(), 0))
            elif low.endswith(".lnk"):
                stem = low[:-4]
                links[stem] = max(last, links.get(stem, 0))
    return exes, links


def prefetch_usage() -> tuple[dict[str, float], bool]:
    """Devuelve (exe_en_mayúsculas → último uso, disponible)."""
    out: dict[str, float] = {}
    if not IS_WINDOWS:
        return out, False
    folder = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return out, False
    for entry in entries:
        if not entry.name.lower().endswith(".pf") or "-" not in entry.name:
            continue
        exe = entry.name.rsplit("-", 1)[0].upper()
        try:
            out[exe] = max(entry.stat().st_mtime, out.get(exe, 0))
        except OSError:
            continue
    return out, bool(entries)


def _clean_path(value: str | None) -> str:
    if not value:
        return ""
    value = os.path.expandvars(str(value).strip())
    if value.startswith('"'):
        value = value[1:].split('"', 1)[0]
    value = re.sub(r",\s*-?\d+$", "", value)
    return value.strip()


def _int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _exes_in(folder: str, max_depth: int = 3, max_dirs: int = 250) -> list[str]:
    found: list[str] = []
    stack = [(folder, 0)]
    visited = 0
    while stack and visited < max_dirs and len(found) < 80:
        current, depth = stack.pop()
        visited += 1
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False) and depth < max_depth:
                            stack.append((entry.path, depth + 1))
                        elif entry.name.lower().endswith(".exe"):
                            found.append(entry.name)
                    except OSError:
                        continue
        except OSError:
            continue
    return found


def read_installed() -> list[dict]:
    if not IS_WINDOWS:
        return []
    import winreg
    sources = [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, 0),
    ]
    seen = set()
    programs = []
    for root, view in sources:
        for sub in reg_subkeys(root, UNINSTALL, view):
            values = {n: v for n, v, _ in reg_values(root, rf"{UNINSTALL}\{sub}", view)}
            name = str(values.get("DisplayName") or "").strip()
            if not name or _int(values.get("SystemComponent")) == 1 or values.get("ParentKeyName") \
                    or _SKIP_NAME.match(name) or str(values.get("ReleaseType", "")).lower() in ("update", "hotfix", "security update"):
                continue
            version = str(values.get("DisplayVersion") or "")
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            install_date = str(values.get("InstallDate") or "")
            programs.append({
                "name": name,
                "version": version,
                "publisher": str(values.get("Publisher") or ""),
                "location": _clean_path(values.get("InstallLocation")),
                "icon": _clean_path(values.get("DisplayIcon")),
                "size": _int(values.get("EstimatedSize")) * 1024,
                "installed": f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:8]}"
                if re.fullmatch(r"\d{8}", install_date) else "",
                "user_install": root == winreg.HKEY_CURRENT_USER,
            })
    return programs


def classify(last_used: float | None, has_evidence_source: bool, now: float | None = None) -> str:
    now = now or time.time()
    if last_used:
        days = (now - last_used) / 86400
        if days < 30:
            return "en_uso"
        if days < 180:
            return "poco_uso"
        return "sin_uso"
    return "sin_registro" if has_evidence_source else "desconocido"


def match_usage(program: dict, exe_names: list[str], prefetch: dict[str, float],
                ua_exes: dict[str, float], ua_links: dict[str, float]) -> tuple[float | None, str]:
    best: float | None = None
    source = ""
    for exe in exe_names:
        if _NOT_USAGE.match(exe):
            continue
        up = exe.upper()
        for table, label in ((prefetch, "Prefetch"), (ua_exes, "UserAssist")):
            ts = table.get(up)
            if ts and (best is None or ts > best):
                best, source = ts, label
    name = program["name"].lower()
    for stem, ts in ua_links.items():
        if len(stem) >= 4 and (stem == name or name.startswith(stem)) and (best is None or ts > best):
            best, source = ts, "Menú Inicio"
    return best, source


def scan(job: Job) -> dict:
    if not IS_WINDOWS:
        job.log("> El inventario de programas solo está disponible en Windows.")
        return {"supported": False, "programs": []}
    job.log("> Leyendo programas instalados del registro...")
    programs = read_installed()
    job.log(f"  {len(programs)} programas encontrados")
    prefetch, prefetch_ok = prefetch_usage()
    ua_exes, ua_links = userassist_usage()
    job.log(f"  Prefetch: {'disponible' if prefetch_ok else 'sin acceso (requiere admin)'} · "
            f"UserAssist: {len(ua_exes) + len(ua_links)} registros")
    size_budget = time.monotonic() + 25
    now = time.time()
    for i, prog in enumerate(programs):
        job.check()
        job.set_progress(i / max(1, len(programs)), f"Analizando: {prog['name']}")
        exes: list[str] = []
        loc = prog["location"]
        if loc and os.path.isdir(loc):
            exes = _exes_in(loc)
            if not prog["size"] and time.monotonic() < size_budget:
                prog["size"] = dir_summary(loc, check=job.check, top_n=0)["size"]
        if prog["icon"].lower().endswith(".exe"):
            exes.append(os.path.basename(prog["icon"]))
        last, source = match_usage(prog, exes, prefetch, ua_exes, ua_links)
        prog["last_used"] = last
        prog["usage_source"] = source
        prog["days_unused"] = int((now - last) // 86400) if last else None
        prog["status"] = classify(last, prefetch_ok and bool(exes), now)
        del prog["icon"]

    programs.sort(key=lambda p: p["size"], reverse=True)
    unused = [p for p in programs if p["status"] in ("sin_uso", "sin_registro")]
    job.log(f"> {len(unused)} programas sin uso reciente "
            f"({sum(p['size'] for p in unused) / 1024 ** 3:.1f} GB).")
    return {
        "supported": True, "programs": programs, "prefetch_available": prefetch_ok,
        "total_size": sum(p["size"] for p in programs),
        "unused_count": len(unused), "unused_size": sum(p["size"] for p in unused),
    }
