"""Basura del sistema: temporales, cachés, papelera, volcados, restos de actualizaciones.

Solo mide y reporta. No borra nada.
"""
from __future__ import annotations

import glob
import os
import time
from dataclasses import dataclass, field

from ..jobs import Job
from ..util import IS_WINDOWS, dir_summary, norm
from ..winapi import recycle_bin_info, reg_get

SAFE = "seguro"
REVIEW = "revisar"


@dataclass
class Category:
    id: str
    name: str
    description: str
    risk: str
    how_to_clean: str
    patterns: list[str] = field(default_factory=list)
    older_than_days: int = 0
    extensions: tuple[str, ...] = ()


_CHROMIUM_CACHE_DIRS = ["Cache", "Code Cache", "GPUCache", r"Service Worker\CacheStorage"]
_BROWSER_HOW = "En el navegador: Ctrl+Shift+Supr → marca solo 'Imágenes y archivos en caché' → Borrar."


def _chromium(user_data: str) -> list[str]:
    pats = [rf"{user_data}\*\{d}" for d in _CHROMIUM_CACHE_DIRS]
    pats += [rf"{user_data}\ShaderCache", rf"{user_data}\GrShaderCache"]
    return pats


def _steam_path() -> str | None:
    if not IS_WINDOWS:
        return None
    import winreg
    path = reg_get(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath")
    return os.path.normpath(path) if path else None


def windows_categories() -> list[Category]:
    cats = [
        Category("temp_user", "Temporales del usuario",
                 "Archivos temporales que dejan los programas al instalar o ejecutarse.", SAFE,
                 "Win+R → escribe %temp% → Ctrl+A → Supr. Omite los que digan 'en uso'.",
                 [r"%TEMP%"]),
        Category("temp_windows", "Temporales de Windows",
                 "Temporales del sistema y de servicios.", SAFE,
                 "Configuración → Sistema → Almacenamiento → Archivos temporales → 'Archivos temporales'.",
                 [r"%SystemRoot%\Temp"]),
        Category("windows_update", "Descargas de Windows Update",
                 "Paquetes de actualizaciones ya instaladas.", SAFE,
                 "Ejecuta 'cleanmgr' como administrador → 'Limpiar archivos del sistema' → 'Limpieza de Windows Update'.",
                 [r"%SystemRoot%\SoftwareDistribution\Download"]),
        Category("delivery_opt", "Optimización de distribución",
                 "Caché de actualizaciones compartidas entre equipos.", SAFE,
                 "Configuración → Almacenamiento → Archivos temporales → 'Archivos de optimización de distribución'.",
                 [r"%SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"]),
        Category("windows_old", "Instalación anterior de Windows (Windows.old)",
                 "Copia de tu Windows anterior. Solo sirve si piensas volver a esa versión.", REVIEW,
                 "cleanmgr como administrador → 'Limpiar archivos del sistema' → 'Instalaciones anteriores de Windows'.",
                 [r"%SystemDrive%\Windows.old"]),
        Category("crash_dumps", "Volcados de errores",
                 "Archivos que Windows y los programas generan al fallar. Solo útiles para diagnosticar.", SAFE,
                 "cleanmgr como administrador → marca 'Archivos de volcado de memoria de errores del sistema'.",
                 [r"%LOCALAPPDATA%\CrashDumps", r"%SystemRoot%\Minidump", r"%SystemRoot%\MEMORY.DMP",
                  r"%SystemRoot%\LiveKernelReports"]),
        Category("wer", "Informes de errores de Windows",
                 "Reportes de fallos ya enviados o en cola.", SAFE,
                 "cleanmgr → marca 'Informes de errores de Windows'.",
                 [r"%ProgramData%\Microsoft\Windows\WER\ReportArchive", r"%ProgramData%\Microsoft\Windows\WER\ReportQueue",
                  r"%LOCALAPPDATA%\Microsoft\Windows\WER"]),
        Category("thumbnails", "Caché de miniaturas e iconos",
                 "Vistas previas de imágenes y videos. Windows las regenera solo.", SAFE,
                 "cleanmgr → marca 'Miniaturas'.",
                 [r"%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db",
                  r"%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db"]),
        Category("windows_logs", "Registros (logs) de Windows",
                 "Registros de instalación y mantenimiento.", SAFE,
                 "cleanmgr como administrador → 'Limpiar archivos del sistema' → 'Archivos de registro de instalación'.",
                 [r"%SystemRoot%\Logs\CBS", r"%SystemRoot%\Logs\DISM", r"%SystemRoot%\Logs\MeasuredBoot"]),
        Category("driver_installers", "Instaladores de drivers extraídos",
                 "Carpetas que dejan los instaladores de NVIDIA, AMD o Intel después de instalar.", REVIEW,
                 "Si el driver ya está instalado, borra la carpeta desde el Explorador.",
                 [r"%SystemDrive%\NVIDIA", r"%SystemDrive%\AMD", r"%ProgramData%\NVIDIA Corporation\Downloader",
                  r"%SystemDrive%\Intel"]),
        Category("chrome", "Caché de Google Chrome", "Páginas e imágenes guardadas para cargar más rápido.", SAFE,
                 _BROWSER_HOW, _chromium(r"%LOCALAPPDATA%\Google\Chrome\User Data")),
        Category("edge", "Caché de Microsoft Edge", "Páginas e imágenes guardadas para cargar más rápido.", SAFE,
                 _BROWSER_HOW, _chromium(r"%LOCALAPPDATA%\Microsoft\Edge\User Data")),
        Category("brave", "Caché de Brave", "Páginas e imágenes guardadas para cargar más rápido.", SAFE,
                 _BROWSER_HOW, _chromium(r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data")),
        Category("opera", "Caché de Opera / Opera GX", "Páginas e imágenes guardadas para cargar más rápido.", SAFE,
                 _BROWSER_HOW, [r"%LOCALAPPDATA%\Opera Software\Opera Stable\Cache",
                                r"%LOCALAPPDATA%\Opera Software\Opera GX Stable\Cache"]),
        Category("firefox", "Caché de Firefox", "Páginas e imágenes guardadas para cargar más rápido.", SAFE,
                 _BROWSER_HOW, [r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2"]),
        Category("apps_cache", "Caché de Discord y Teams", "Imágenes y datos temporales de estas apps.", SAFE,
                 "Cierra la app y borra las carpetas Cache / Code Cache / GPUCache que aparecen abajo.",
                 [r"%APPDATA%\discord\Cache", r"%APPDATA%\discord\Code Cache", r"%APPDATA%\discord\GPUCache",
                  r"%APPDATA%\Microsoft\Teams\Cache", r"%APPDATA%\Microsoft\Teams\Service Worker\CacheStorage",
                  r"%LOCALAPPDATA%\Packages\MSTeams_*\LocalCache\Microsoft\MSTeams\EBWebView\Default\Cache"]),
        Category("spotify", "Caché de Spotify", "Canciones en caché para streaming. No son tus descargas offline.",
                 REVIEW, "Spotify → Configuración → Almacenamiento → 'Borrar caché'.",
                 [r"%LOCALAPPDATA%\Spotify\Data"]),
        Category("dev_cache", "Caché de desarrollo (pip, npm, yarn)",
                 "Paquetes descargados que se pueden volver a bajar.", SAFE,
                 "Ejecuta 'pip cache purge' y 'npm cache clean --force'.",
                 [r"%LOCALAPPDATA%\pip\Cache", r"%LOCALAPPDATA%\npm-cache", r"%APPDATA%\npm-cache",
                  r"%LOCALAPPDATA%\Yarn\Cache"]),
        Category("old_downloads", "Instaladores y comprimidos viejos en Descargas",
                 "Instaladores (.exe, .msi), comprimidos e ISOs con más de 30 días en Descargas.", REVIEW,
                 "Revisa la lista: si el programa ya está instalado o el comprimido ya se extrajo, bórralo a mano.",
                 [r"%USERPROFILE%\Downloads"], older_than_days=30,
                 extensions=(".exe", ".msi", ".zip", ".rar", ".7z", ".iso", ".tar", ".gz")),
    ]
    steam = _steam_path()
    if steam:
        cats.append(Category("steam", "Steam: caché web, logs y volcados",
                             "Caché del navegador interno de Steam y reportes de fallos de juegos.", SAFE,
                             "Steam → Configuración → En partida / Descargas → 'Borrar caché de descargas'; "
                             "las carpetas de logs y dumps se pueden vaciar a mano.",
                             [steam + r"\appcache\httpcache", steam + r"\logs", steam + r"\dumps",
                              steam + r"\steamapps\downloading"]))
    return cats


def posix_categories() -> list[Category]:
    home = os.path.expanduser("~")
    return [
        Category("user_cache", "Caché del usuario", "Cachés de aplicaciones (~/.cache).", SAFE,
                 "Borra el contenido de ~/.cache con las apps cerradas.", [home + "/.cache"]),
        Category("trash", "Papelera", "Archivos enviados a la papelera.", SAFE,
                 "Vacía la papelera desde el gestor de archivos.", [home + "/.local/share/Trash"]),
        Category("tmp", "Temporales", "Archivos temporales del sistema.", SAFE,
                 "Se limpian solos al reiniciar.", ["/tmp", "/var/tmp"]),
        Category("old_downloads", "Instaladores y comprimidos viejos en Descargas",
                 "Comprimidos e imágenes de disco con más de 30 días.", REVIEW,
                 "Revisa la lista y borra a mano lo que ya no necesites.",
                 [home + "/Downloads", home + "/Descargas"], older_than_days=30,
                 extensions=(".zip", ".rar", ".7z", ".iso", ".tar", ".gz", ".deb", ".appimage")),
    ]


def _expand(pattern: str) -> list[str]:
    expanded = os.path.expandvars(pattern)
    if "%" in expanded and IS_WINDOWS:
        return []  # variable inexistente
    if any(ch in expanded for ch in "*?["):
        return glob.glob(expanded)
    return [expanded] if os.path.exists(expanded) else []


def scan(job: Job) -> dict:
    cats = windows_categories() if IS_WINDOWS else posix_categories()
    results = []
    total_steps = len(cats) + 1
    job.log(f"> Analizando {len(cats)} categorías de basura...")
    for i, cat in enumerate(cats):
        job.check()
        job.set_progress(i / total_steps, f"Midiendo: {cat.name}")
        paths: list[str] = []
        seen: set[str] = set()
        for pat in cat.patterns:
            for p in _expand(pat):
                key = norm(p)
                if key not in seen:
                    seen.add(key)
                    paths.append(p)
        if not paths:
            continue
        older = time.time() - cat.older_than_days * 86400 if cat.older_than_days else None
        size = files = denied = 0
        top: list[dict] = []
        for p in paths:
            s = dir_summary(p, check=job.check, older_than=older, extensions=cat.extensions)
            size += s["size"]
            files += s["files"]
            denied += s["denied"]
            top.extend(s["top"])
        if size == 0 and files == 0:
            continue
        top.sort(key=lambda x: x["size"], reverse=True)
        results.append({
            "id": cat.id, "name": cat.name, "description": cat.description, "risk": cat.risk,
            "how_to_clean": cat.how_to_clean, "size": size, "files": files, "denied": denied,
            "paths": paths, "top": top[:10],
        })
        job.log(f"  [{'OK' if not denied else '~~'}] {cat.name}: {files} archivos")

    job.set_progress(len(cats) / total_steps, "Consultando la Papelera")
    rb = recycle_bin_info()
    if rb and rb["size"] > 0:
        results.append({
            "id": "recycle_bin", "name": "Papelera de reciclaje",
            "description": f"{rb['items']} elementos que ya mandaste a la papelera.", "risk": SAFE,
            "how_to_clean": "Clic derecho en la Papelera del escritorio → 'Vaciar papelera de reciclaje'.",
            "size": rb["size"], "files": rb["items"], "denied": 0, "paths": [], "top": [],
        })
        job.log(f"  [OK] Papelera: {rb['items']} elementos")

    results.sort(key=lambda r: r["size"], reverse=True)
    total = sum(r["size"] for r in results)
    safe = sum(r["size"] for r in results if r["risk"] == SAFE)
    partial = any(r["denied"] for r in results)
    job.log(f"> Basura detectada: {len(results)} categorías.")
    if partial:
        job.log("> Algunas carpetas no se pudieron leer. Ejecuta como administrador para medir todo.")
    return {"categories": results, "total": total, "safe_total": safe, "partial": partial}
