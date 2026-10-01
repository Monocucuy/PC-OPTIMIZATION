"""Servidor HTTP local (solo 127.0.0.1) que sirve la interfaz y la API JSON.

Protecciones: solo escucha en loopback, valida el encabezado Host (contra DNS rebinding)
y exige un token aleatorio por sesión en cada llamada a la API (contra CSRF).
"""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import config, sysinfo
from .disk import duplicates, junk, large_files, programs
from .jobs import JobError, JobManager
from .perf import benchmark
from .perf.monitor import MONITOR
from .security import defender, persistence, processes, virustotal
from .winapi import open_location

WEB_DIR = Path(__file__).with_name("web")
MAX_BODY = 1024 * 1024


class App:
    def __init__(self, port: int) -> None:
        self.port = port
        self.token = secrets.token_urlsafe(24)
        self.jobs = JobManager()
        self._register_jobs()

    # ------------------------------------------------------------ trabajos
    def _register_jobs(self) -> None:
        def large(job, **_):
            cfg = config.load()
            return large_files.scan(job, cfg["scan_roots"], cfg["large_min_mb"], cfg["unused_days"],
                                    cfg["exclude_paths"])

        def dups(job, **_):
            cfg = config.load()
            return duplicates.scan(job, cfg["scan_roots"], cfg["dup_min_mb"], cfg["dup_skip_appdata"],
                                   cfg["exclude_paths"])

        def vt(job, paths=None, **_):
            if not isinstance(paths, list):
                raise JobError("Faltan las rutas a consultar.")
            return virustotal.lookup(job, [str(p) for p in paths if os.path.isfile(str(p))])

        def bench(job, names=None, quick=False, **_):
            return benchmark.run(job, names if isinstance(names, list) else [], self.port, bool(quick))

        self.jobs.register("junk", lambda job, **_: junk.scan(job))
        self.jobs.register("large", large)
        self.jobs.register("duplicates", dups)
        self.jobs.register("programs", lambda job, **_: programs.scan(job))
        self.jobs.register("processes", lambda job, **_: processes.scan(job))
        self.jobs.register("persistence", lambda job, **_: persistence.scan(job))
        self.jobs.register("defender_status", lambda job, **_: defender.status(job))
        self.jobs.register("defender_scan", lambda job, **_: defender.quick_scan(job))
        self.jobs.register("virustotal", vt)
        self.jobs.register("benchmark", bench)

    # ------------------------------------------------------------ API
    def api(self, method: str, path: str, query: dict, body: dict) -> tuple[int, object]:
        parts = [p for p in path.split("/") if p][1:]  # sin 'api'
        route = "/".join(parts)

        if method == "GET" and route == "system":
            return 200, sysinfo.info()
        if route == "config":
            if method == "GET":
                return 200, config.public_view(config.load())
            if method == "POST":
                return 200, config.public_view(config.save(body))
        if method == "POST" and route == "jobs":
            kind = str(body.get("kind", ""))
            params = body.get("params") or {}
            if not isinstance(params, dict):
                return 400, {"error": "params debe ser un objeto"}
            try:
                job = self.jobs.start(kind, params)
            except JobError as exc:
                return 409, {"error": str(exc)}
            return 200, {"id": job.id}
        if len(parts) >= 2 and parts[0] == "jobs":
            job = self.jobs.get(parts[1])
            if job is None:
                return 404, {"error": "Trabajo no encontrado"}
            if method == "GET" and len(parts) == 2:
                try:
                    since = int(query.get("since", ["0"])[0])
                except ValueError:
                    since = 0
                return 200, job.snapshot(since)
            if method == "POST" and len(parts) == 3 and parts[2] == "cancel":
                job.cancel()
                return 200, {"ok": True}
        if method == "GET" and route == "results":
            return 200, self.jobs.latest()
        if method == "GET" and route == "perf/live":
            try:
                since = float(query.get("since", ["0"])[0])
            except ValueError:
                since = 0.0
            return 200, MONITOR.snapshot(since)
        if method == "GET" and route == "perf/candidates":
            return 200, benchmark.candidates(self.port)
        if method == "GET" and route == "perf/history":
            return 200, {"history": benchmark.history()}
        if method == "POST" and route == "perf/resume":
            return 200, {"resumed": benchmark.resume_all()}
        if method == "POST" and route == "open":
            ok = open_location(str(body.get("path", "")))
            return (200, {"ok": True}) if ok else (404, {"error": "La ruta ya no existe"})
        return 404, {"error": f"Ruta desconocida: {method} {path}"}


def make_handler(app: App):
    allowed_hosts = {f"127.0.0.1:{app.port}", f"localhost:{app.port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "MatrixScan"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # silencioso: la consola muestra solo lo importante
            pass

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj) -> None:
            body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8", {"Cache-Control": "no-store"})

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _serve_static(self, rel: str) -> None:
            target = (WEB_DIR / rel).resolve()
            if WEB_DIR.resolve() not in target.parents or not target.is_file():
                self._send(404, b"404", "text/plain")
                return
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            self._send(200, target.read_bytes(), ctype, {"Cache-Control": "no-cache"})

        def _dispatch(self, method: str) -> None:
            if not self._host_ok():
                self._send(403, b"Host no permitido", "text/plain")
                return
            url = urlparse(self.path)
            if url.path.startswith("/api/"):
                if not secrets.compare_digest(self.headers.get("X-MS-Token", ""), app.token):
                    self._json(403, {"error": "Token inválido"})
                    return
                body = {}
                if method == "POST":
                    length = int(self.headers.get("Content-Length") or 0)
                    if length > MAX_BODY:
                        self._json(413, {"error": "Petición demasiado grande"})
                        return
                    raw = self.rfile.read(length) if length else b"{}"
                    try:
                        body = json.loads(raw.decode("utf-8") or "{}")
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        self._json(400, {"error": "JSON inválido"})
                        return
                    if not isinstance(body, dict):
                        body = {}
                try:
                    status, obj = app.api(method, url.path, parse_qs(url.query), body)
                except Exception as exc:  # noqa: BLE001
                    status, obj = 500, {"error": f"{type(exc).__name__}: {exc}"}
                self._json(status, obj)
                return
            if method != "GET":
                self._send(HTTPStatus.METHOD_NOT_ALLOWED, b"", "text/plain")
                return
            if url.path in ("/", "/index.html"):
                html = (WEB_DIR / "index.html").read_text(encoding="utf-8").replace("{{TOKEN}}", app.token)
                csp = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8",
                           {"Content-Security-Policy": csp, "Cache-Control": "no-store"})
                return
            if url.path.startswith("/static/"):
                self._serve_static(url.path[len("/static/"):])
                return
            self._send(404, b"404", "text/plain")

        def do_GET(self):
            self._dispatch("GET")

        def do_HEAD(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def create_server(port: int) -> tuple[Server, App]:
    """Crea el servidor en el puerto pedido o en el siguiente libre."""
    last_error: OSError | None = None
    for candidate in list(range(port, port + 20)) + [0]:
        try:
            # El handler necesita el puerto real: se crea con un App provisional y se ajusta
            app = App(candidate)
            server = Server(("127.0.0.1", candidate), make_handler(app))
            real_port = server.server_address[1]
            if real_port != candidate:
                app.port = real_port
                server.RequestHandlerClass = make_handler(app)
            return server, app
        except OSError as exc:
            last_error = exc
    raise last_error or OSError("No hay puertos libres")
