"""Trabajos en segundo plano con progreso, log y cancelación."""
from __future__ import annotations

import threading
import time
import traceback
import uuid
from typing import Callable


class Cancelled(Exception):
    pass


class JobError(Exception):
    """Error esperado que se muestra tal cual al usuario."""


class Job:
    def __init__(self, kind: str, params: dict) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.params = params
        self.status = "running"
        self.progress: float | None = None
        self.message = ""
        self.result = None
        self.error: str | None = None
        self.started = time.time()
        self.finished: float | None = None
        self._log: list[str] = []
        self._cancel = threading.Event()
        self._lock = threading.Lock()

    # --- API para los escáneres
    def log(self, line: str) -> None:
        with self._lock:
            self._log.append(line)
            if len(self._log) > 2000:
                del self._log[:500]

    def set_progress(self, fraction: float | None, message: str | None = None) -> None:
        with self._lock:
            self.progress = None if fraction is None else max(0.0, min(1.0, fraction))
            if message is not None:
                self.message = message

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check(self) -> None:
        if self._cancel.is_set():
            raise Cancelled()

    def sleep(self, seconds: float) -> None:
        """Espera interrumpible por cancelación."""
        if self._cancel.wait(seconds):
            raise Cancelled()

    def cancel(self) -> None:
        self._cancel.set()

    # --- API para el servidor
    def snapshot(self, since: int = 0) -> dict:
        with self._lock:
            total = len(self._log)
            since = max(0, min(since, total))
            data = {
                "id": self.id,
                "kind": self.kind,
                "status": self.status,
                "progress": self.progress,
                "message": self.message,
                "log": self._log[since:],
                "log_total": total,
                "elapsed": round((self.finished or time.time()) - self.started, 1),
                "error": self.error,
            }
            if self.status != "running":
                data["result"] = self.result
            return data


class JobManager:
    EXCLUSIVE = {"benchmark"}

    def __init__(self) -> None:
        self._handlers: dict[str, Callable] = {}
        self._jobs: dict[str, Job] = {}
        self._latest: dict[str, dict] = {}
        self._lock = threading.Lock()

    def register(self, kind: str, handler: Callable) -> None:
        self._handlers[kind] = handler

    def running(self) -> list[Job]:
        with self._lock:
            return [j for j in self._jobs.values() if j.status == "running"]

    def start(self, kind: str, params: dict) -> Job:
        if kind not in self._handlers:
            raise JobError(f"Tipo de trabajo desconocido: {kind}")
        running = self.running()
        if any(j.kind in self.EXCLUSIVE for j in running):
            raise JobError("Hay un benchmark en curso. Espera a que termine para no alterar la medición.")
        if kind in self.EXCLUSIVE and running:
            raise JobError("Espera a que terminen los escaneos en curso antes del benchmark.")
        if any(j.kind == kind for j in running):
            raise JobError("Ese análisis ya se está ejecutando.")
        job = Job(kind, params)
        with self._lock:
            self._jobs[job.id] = job
            finished = [j for j in self._jobs.values() if j.status != "running"]
            for old in sorted(finished, key=lambda j: j.started)[:-30]:
                self._jobs.pop(old.id, None)
        threading.Thread(target=self._run, args=(job,), name=f"job-{kind}", daemon=True).start()
        return job

    def _run(self, job: Job) -> None:
        handler = self._handlers[job.kind]
        try:
            job.result = handler(job, **job.params)
            job.status = "done"
            job.set_progress(1.0)
        except Cancelled:
            job.status = "cancelled"
            job.log("> Cancelado por el usuario.")
        except JobError as exc:
            job.status = "error"
            job.error = str(exc)
            job.log(f"> ERROR: {exc}")
        except Exception as exc:  # noqa: BLE001 - se reporta al usuario
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.log(f"> ERROR inesperado: {job.error}")
            traceback.print_exc()
        finally:
            job.finished = time.time()
            if job.status == "done":
                with self._lock:
                    self._latest[job.kind] = {"result": job.result, "finished": job.finished}

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def latest(self) -> dict:
        with self._lock:
            return dict(self._latest)
