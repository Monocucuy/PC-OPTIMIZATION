"""Punto de entrada: python -m matrixscan"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import webbrowser

from . import __version__
from .perf import benchmark
from .perf.monitor import MONITOR
from .server import create_server
from .util import IS_WINDOWS
from .winapi import is_admin

GREEN = "\033[92m"
DIM = "\033[32m"
RESET = "\033[0m"

BANNER = r"""
  __  __    _  _____ ____  _____  __    ____   ____    _    _   _
 |  \/  |  / \|_   _|  _ \|_ _\ \/ /   / ___| / ___|  / \  | \ | |
 | |\/| | / _ \ | | | |_) || | \  /____\___ \| |     / _ \ |  \| |
 | |  | |/ ___ \| | |  _ < | | /  \_____|__) | |___ / ___ \| |\  |
 |_|  |_/_/   \_\_| |_| \_\___/_/\_\   |____/ \____/_/   \_\_| \_|
"""


def _find_edge() -> str | None:
    for var in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if base:
            path = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
            if os.path.isfile(path):
                return path
    return shutil.which("msedge")


def open_ui(url: str) -> None:
    """Abre la interfaz como ventana de aplicación (Edge --app) o en el navegador por defecto."""
    if IS_WINDOWS:
        edge = _find_edge()
        if edge:
            try:
                subprocess.Popen([edge, f"--app={url}", "--window-size=1440,920"])
                return
            except OSError:
                pass
    webbrowser.open(url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="matrixscan", description="Análisis de disco, seguridad y rendimiento")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true", help="No abrir la interfaz automáticamente")
    args = parser.parse_args(argv)

    if IS_WINDOWS:
        os.system("")  # activa los colores ANSI en la consola de Windows 10
    recovered = benchmark.recover_suspended()
    server, app = create_server(args.port)
    url = f"http://127.0.0.1:{app.port}/"
    MONITOR.start()

    print(GREEN + BANNER + RESET)
    print(f"{DIM}  v{__version__} · Solo lectura: MatrixScan no borra ni modifica tus archivos.{RESET}")
    print(f"{GREEN}  > Interfaz: {url}{RESET}")
    if recovered:
        print(f"{GREEN}  > Se reanudaron {recovered} procesos que quedaron en pausa en la sesión anterior.{RESET}")
    if not is_admin():
        print(f"{DIM}  > Sin permisos de administrador: algunas mediciones quedarán incompletas.{RESET}")
    print(f"{DIM}  > Cierra esta ventana (o Ctrl+C) para detener MatrixScan.{RESET}\n")
    sys.stdout.flush()

    if not args.no_browser:
        threading.Timer(0.6, open_ui, args=(url,)).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        benchmark.resume_all()
        server.server_close()
        print(f"{GREEN}  > MatrixScan detenido.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
