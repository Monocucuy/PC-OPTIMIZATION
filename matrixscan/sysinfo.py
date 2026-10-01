"""Información general del equipo."""
from __future__ import annotations

import platform
import socket
import sys
import time

import psutil

from . import __version__
from .util import IS_WINDOWS
from .winapi import cpu_name, is_admin

_static: dict | None = None


def _os_name() -> str:
    if IS_WINDOWS:
        release, build = platform.release(), platform.version()
        # Windows 11 reporta release "10"; el build >= 22000 lo delata
        try:
            if int(build.split(".")[-1]) >= 22000 and release == "10":
                release = "11"
        except ValueError:
            pass
        edition = ""
        try:
            edition = platform.win32_edition() or ""
        except AttributeError:
            pass
        return f"Windows {release} {edition} (build {build})".replace("  ", " ")
    return f"{platform.system()} {platform.release()}"


def disks() -> list[dict]:
    out = []
    seen = set()
    for part in psutil.disk_partitions(all=False):
        if "cdrom" in part.opts or not part.fstype or part.mountpoint in seen:
            continue
        if not IS_WINDOWS and not (part.mountpoint == "/" or part.mountpoint.startswith(("/home", "/mnt", "/media"))):
            continue
        seen.add(part.mountpoint)
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        out.append({
            "mount": part.mountpoint,
            "fstype": part.fstype,
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": usage.percent,
        })
    return out


def info() -> dict:
    global _static
    if _static is None:
        _static = {
            "hostname": socket.gethostname(),
            "os": _os_name(),
            "is_windows": IS_WINDOWS,
            "cpu": cpu_name(),
            "cores_physical": psutil.cpu_count(logical=False) or 0,
            "cores_logical": psutil.cpu_count(logical=True) or 0,
            "python": sys.version.split()[0],
            "version": __version__,
        }
    vm = psutil.virtual_memory()
    data = dict(_static)
    data.update({
        "admin": is_admin(),
        "ram_total": vm.total,
        "ram_percent": vm.percent,
        "uptime_s": int(time.time() - psutil.boot_time()),
        "disks": disks(),
    })
    return data
