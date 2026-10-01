"""Monitor en vivo de CPU, RAM, disco, red y consumo por proceso."""
from __future__ import annotations

import os
import threading
import time
from collections import deque

import psutil

from ..util import IS_WINDOWS
from ..winapi import visible_window_pids

HISTORY = 120  # segundos de historial para las gráficas
PROC_INTERVAL = 2.0

# Procesos que nunca se deben pausar: el sistema dejaría de responder o no se permite
PROTECTED = {
    "system", "system idle process", "registry", "memory compression", "secure system", "idle",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
    "svchost.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe", "audiodg.exe", "conhost.exe",
    "sihost.exe", "ctfmon.exe", "taskhostw.exe", "msmpeng.exe", "nissrv.exe", "mssense.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe", "wudfhost.exe", "spoolsv.exe",
    "runtimebroker.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "searchapp.exe",
    "searchhost.exe", "textinputhost.exe", "applicationframehost.exe", "smartscreen.exe",
    "taskmgr.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "openconsole.exe",
    "python.exe", "pythonw.exe", "py.exe", "lsm.exe", "dllhost.exe", "wmiprvse.exe",
    "nvcontainer.exe", "nvdisplay.container.exe", "atiesrxx.exe", "atieclxx.exe", "igfxem.exe",
    "systemd", "init", "kthreadd", "sshd", "dbus-daemon", "xorg", "gnome-shell",
}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
            "msedgewebview2.exe", "chrome", "firefox", "chromium", "brave", "msedge"}


class Monitor:
    def __init__(self) -> None:
        self.history: deque = deque(maxlen=HISTORY)
        self.groups: list[dict] = []
        self._cpu_hist: dict[str, deque] = {}
        self._io_prev: dict[int, tuple[int, float]] = {}
        self._disk_prev = None
        self._net_prev = None
        self._lock = threading.Lock()
        self._started = False
        self._services: dict[int, str] = {}
        self._services_at = 0.0
        self.ncpu = psutil.cpu_count() or 1

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        psutil.cpu_percent(None)
        threading.Thread(target=self._loop, name="monitor", daemon=True).start()

    # ------------------------------------------------------------ muestreo
    def _loop(self) -> None:
        last_proc = 0.0
        while True:
            t0 = time.monotonic()
            try:
                self._sample_system()
                if t0 - last_proc >= PROC_INTERVAL:
                    last_proc = t0
                    self._sample_processes()
            except Exception:  # noqa: BLE001 - el monitor nunca debe morir
                pass
            time.sleep(max(0.1, 1.0 - (time.monotonic() - t0)))

    def _sample_system(self) -> None:
        now = time.monotonic()
        cpu_cores = psutil.cpu_percent(None, percpu=True)
        cpu = sum(cpu_cores) / max(1, len(cpu_cores))
        vm = psutil.virtual_memory()
        disk = psutil.disk_io_counters()
        net = psutil.net_io_counters()
        read = write = sent = recv = 0.0
        if disk and self._disk_prev:
            dt = now - self._disk_prev[1]
            read = max(0, disk.read_bytes - self._disk_prev[0].read_bytes) / dt
            write = max(0, disk.write_bytes - self._disk_prev[0].write_bytes) / dt
        if net and self._net_prev:
            dt = now - self._net_prev[1]
            sent = max(0, net.bytes_sent - self._net_prev[0].bytes_sent) / dt
            recv = max(0, net.bytes_recv - self._net_prev[0].bytes_recv) / dt
        self._disk_prev = (disk, now) if disk else None
        self._net_prev = (net, now) if net else None
        sample = {
            "t": time.time(), "cpu": round(cpu, 1), "cores": [round(c) for c in cpu_cores],
            "ram": round(vm.percent, 1), "ram_used": vm.total - vm.available, "ram_total": vm.total,
            "disk_read": read, "disk_write": write, "net_sent": sent, "net_recv": recv,
        }
        with self._lock:
            self.history.append(sample)

    def _service_map(self) -> dict[int, str]:
        if not IS_WINDOWS:
            return {}
        if time.monotonic() - self._services_at > 60:
            services: dict[int, str] = {}
            try:
                for svc in psutil.win_service_iter():
                    try:
                        pid = svc.pid()
                        if pid:
                            services.setdefault(pid, svc.display_name())
                    except psutil.Error:
                        continue
            except (psutil.Error, OSError):
                pass
            self._services = services
            self._services_at = time.monotonic()
        return self._services

    def _sample_processes(self) -> None:
        now = time.monotonic()
        own = os.getpid()
        visible = visible_window_pids()
        services = self._service_map()
        groups: dict[str, dict] = {}
        seen_pids = set()
        for p in psutil.process_iter(["name", "memory_info"]):
            pid = p.pid
            if pid == 0 or pid == own:
                continue
            seen_pids.add(pid)
            name = p.info.get("name") or f"pid {pid}"
            try:
                cpu = p.cpu_percent(None) / self.ncpu
            except psutil.Error:
                continue
            mem = p.info.get("memory_info")
            rss = mem.rss if mem else 0
            io_rate = 0.0
            try:
                io = p.io_counters()
                total_io = io.read_bytes + io.write_bytes
                prev = self._io_prev.get(pid)
                if prev:
                    io_rate = max(0, total_io - prev[0]) / max(0.1, now - prev[1])
                self._io_prev[pid] = (total_io, now)
            except (psutil.Error, AttributeError, OSError):
                pass
            key = name.lower()
            g = groups.get(key)
            if g is None:
                g = groups[key] = {"name": name, "count": 0, "cpu": 0.0, "rss": 0, "io": 0.0,
                                   "foreground": False, "service": "", "pids": []}
            g["count"] += 1
            g["cpu"] += cpu
            g["rss"] += rss
            g["io"] += io_rate
            g["pids"].append(pid)
            if pid in visible:
                g["foreground"] = True
            if pid in services and not g["service"]:
                g["service"] = services[pid]
        for pid in list(self._io_prev):
            if pid not in seen_pids:
                del self._io_prev[pid]
        for key, g in groups.items():
            hist = self._cpu_hist.setdefault(key, deque(maxlen=30))
            hist.append(g["cpu"])
            g["cpu_avg"] = round(sum(hist) / len(hist), 2)
            g["cpu"] = round(g["cpu"], 2)
            g["protected"] = key in PROTECTED
            g["browser"] = key in BROWSERS
        for key in list(self._cpu_hist):
            if key not in groups:
                del self._cpu_hist[key]
        ordered = sorted(groups.values(), key=lambda g: (g["cpu_avg"], g["rss"]), reverse=True)
        with self._lock:
            self.groups = ordered

    # ------------------------------------------------------------ lectura
    def snapshot(self, since: float = 0, top: int = 25) -> dict:
        with self._lock:
            hist = [s for s in self.history if s["t"] > since]
            groups = [dict(g, pids=g["pids"][:10]) for g in self.groups[:top]]
            all_groups = list(self.groups)
        bg = [g for g in all_groups if not g["foreground"] and g["name"].lower() not in ("system idle process", "idle")]
        return {
            "history": hist,
            "processes": groups,
            "background": {
                "cpu": round(sum(g["cpu_avg"] for g in bg), 1),
                "rss": sum(g["rss"] for g in bg),
                "count": sum(g["count"] for g in bg),
            },
            "foreground_count": sum(g["count"] for g in all_groups if g["foreground"]),
        }

    def groups_by_name(self) -> dict[str, dict]:
        with self._lock:
            return {g["name"].lower(): g for g in self.groups}


MONITOR = Monitor()
