"""Llamadas nativas de Windows vía ctypes/winreg. En otros sistemas degradan sin error."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys

from .util import IS_WINDOWS

if IS_WINDOWS:
    import winreg
    from ctypes import wintypes


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def recycle_bin_info() -> dict | None:
    """Tamaño y número de elementos de la Papelera de todas las unidades."""
    if not IS_WINDOWS:
        return None

    class SHQUERYRBINFO(ctypes.Structure):
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            _pack_ = 1
        _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong),
                    ("i64NumItems", ctypes.c_longlong)]

    info = SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(info)
    hr = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
    if hr != 0:
        return None
    return {"size": int(info.i64Size), "items": int(info.i64NumItems)}


_console_handlers: list = []  # referencias vivas: si el callback se recolecta, Windows llamaría a memoria liberada


def install_console_close_handler(callback) -> None:
    """Ejecuta callback cuando se cierra la consola, se cierra sesión o se apaga el equipo."""
    if not IS_WINDOWS:
        return

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    def handler(_event):
        try:
            callback()
        except Exception:  # noqa: BLE001 - nunca bloquear el cierre
            pass
        return False  # deja que el manejador por defecto siga (cerrar / KeyboardInterrupt)

    if ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True):
        _console_handlers.append(handler)


def visible_window_pids() -> set[int]:
    """PIDs con al menos una ventana visible y con título (procesos en primer plano)."""
    if not IS_WINDOWS:
        return set()
    user32 = ctypes.windll.user32
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    # argtypes explícitos: sin ellos ctypes convierte los HWND a int de 32 bits
    user32.EnumWindows.argtypes = [enum_proc, wintypes.LPARAM]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    pids: set[int] = set()
    try:
        dwmapi = ctypes.windll.dwmapi
        dwmapi.DwmGetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    except (OSError, AttributeError):
        dwmapi = None

    @enum_proc
    def callback(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd) or user32.GetWindowTextLengthW(hwnd) == 0:
            return True
        if dwmapi is not None:
            cloaked = wintypes.DWORD(0)
            # DWMWA_CLOAKED = 14: ventanas UWP suspendidas u ocultas por el sistema
            if dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0 \
                    and cloaked.value:
                return True
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pids.add(int(pid.value))
        return True

    user32.EnumWindows(callback, 0)
    return pids


def reg_values(root, subkey: str, view: int = 0) -> list[tuple[str, object, int]]:
    """Lista (nombre, valor, tipo) de una clave del registro. Vacío si no existe."""
    if not IS_WINDOWS:
        return []
    out = []
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | view) as key:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumValue(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def reg_subkeys(root, subkey: str, view: int = 0) -> list[str]:
    if not IS_WINDOWS:
        return []
    out = []
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | view) as key:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def reg_get(root, subkey: str, name: str, view: int = 0):
    if not IS_WINDOWS:
        return None
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | view) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def last_access_tracking() -> dict:
    """Indica si NTFS actualiza la fecha de último acceso (afecta 'archivos sin abrir')."""
    if not IS_WINDOWS:
        return {"known": True, "enabled": True, "note": "El sistema de archivos registra el último acceso."}
    value = reg_get(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem",
                    "NtfsDisableLastAccessUpdate")
    if value is None:
        return {"known": False, "enabled": False,
                "note": "No se pudo leer si Windows registra el último acceso; se usa la fecha de modificación."}
    enabled = (int(value) & 1) == 0
    note = ("Windows registra el último acceso: la fecha es confiable." if enabled else
            "Windows NO registra el último acceso en este equipo: se usa la fecha de modificación, "
            "así que algunos archivos pueden haberse abierto más recientemente.")
    return {"known": True, "enabled": enabled, "note": note}


def cpu_name() -> str:
    if IS_WINDOWS:
        name = reg_get(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                       "ProcessorNameString")
        if name:
            return str(name).strip()
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    import platform
    return platform.processor() or "CPU desconocida"


def open_location(path: str) -> bool:
    """Abre el Explorador con el archivo seleccionado (solo lectura, no modifica nada)."""
    if not os.path.exists(path) or '"' in path:
        return False
    if IS_WINDOWS:
        if os.path.isdir(path):
            subprocess.Popen(["explorer", os.path.normpath(path)])
        else:
            subprocess.Popen(f'explorer /select,"{os.path.normpath(path)}"')
        return True
    target = path if os.path.isdir(path) else os.path.dirname(path)
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    try:
        subprocess.Popen([opener, target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except OSError:
        return False
