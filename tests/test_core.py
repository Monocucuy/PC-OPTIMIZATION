import http.client
import json
import threading
import time

import pytest

from matrixscan import config
from matrixscan.jobs import Job, JobError, JobManager
from matrixscan.perf.benchmark import compare


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path))


def test_config_validation_and_masking():
    cfg = config.save({"large_min_mb": "-5", "unused_days": 99999, "scan_roots": [], "vt_api_key": "  abcd1234efgh  ",
                       "unknown": 1})
    assert cfg["large_min_mb"] == 1 and cfg["unused_days"] == 3650
    assert cfg["scan_roots"] == config.defaults()["scan_roots"]
    view = config.public_view(cfg)
    assert "vt_api_key" not in view and view["has_vt_key"] and view["vt_key_hint"] == "••••efgh"


def test_job_manager_exclusive_benchmark():
    jm = JobManager()
    gate = threading.Event()
    jm.register("slow", lambda job, **_: gate.wait(5))
    jm.register("benchmark", lambda job, **_: None)
    jm.start("slow", {})
    with pytest.raises(JobError):
        jm.start("benchmark", {})
    with pytest.raises(JobError):
        jm.start("slow", {})
    gate.set()
    time.sleep(0.2)
    assert jm.start("benchmark", {})


def test_job_cancel_and_log():
    jm = JobManager()

    def work(job: Job, **_):
        job.log("> inicio")
        while True:
            job.sleep(0.05)

    jm.register("work", work)
    j = jm.start("work", {})
    time.sleep(0.15)
    j.cancel()
    time.sleep(0.2)
    snap = j.snapshot()
    assert snap["status"] == "cancelled"
    assert snap["log"][0] == "> inicio"
    assert j.snapshot(since=snap["log_total"])["log"] == []


def test_benchmark_comparison_math():
    base = {k: {"value": v, "spread": 2.0} for k, v in
            {"cpu_multi": 100, "cpu_single": 50, "memory": 10, "disk_write": 200, "disk_latency": 2.0}.items()}
    paused = {k: {"value": v, "spread": 2.0} for k, v in
              {"cpu_multi": 150, "cpu_single": 51, "memory": 10, "disk_write": 300, "disk_latency": 1.0}.items()}
    rows, loss = compare(base, paused)
    by = {r["test"]: r for r in rows}
    assert by["cpu_multi"]["gain_pct"] == 50.0 and by["cpu_multi"]["significant"]
    assert not by["cpu_single"]["significant"]  # +2% está dentro del margen
    assert by["disk_latency"]["gain_pct"] == 50.0  # menos latencia = mejora
    assert loss == pytest.approx(50 * 0.35 + 50 * 0.2 + 50 * 0.15)


def test_server_security_and_api():
    from matrixscan.server import create_server
    server, app = create_server(18765)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        def req(method, path, headers=None, body=None):
            c = http.client.HTTPConnection("127.0.0.1", app.port, timeout=5)
            c.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers or {})
            r = c.getresponse()
            return r.status, r.read()

        status, html = req("GET", "/")
        assert status == 200 and app.token.encode() in html
        assert req("GET", "/api/system")[0] == 403                                 # sin token
        assert req("GET", "/", {"Host": "evil.example:80"})[0] == 403              # DNS rebinding
        assert req("GET", "/static/../server.py")[0] == 404                         # path traversal
        ok = {"X-MS-Token": app.token}
        status, body = req("GET", "/api/system", ok)
        assert status == 200 and "cpu" in json.loads(body)
        status, body = req("POST", "/api/jobs", ok, {"kind": "nope"})
        assert status == 409
        status, body = req("POST", "/api/open", ok, {"path": "/no/existe"})
        assert status == 404
    finally:
        server.shutdown()
        server.server_close()


def _detached_sleep():
    """Proceso 'sleep' que no es hijo de pytest (los hijos propios nunca se pausan)."""
    import subprocess
    import psutil
    out = subprocess.run(["sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!"], capture_output=True, text=True)
    return psutil.Process(int(out.stdout.strip()))


def test_benchmark_pauses_then_always_resumes(monkeypatch):
    import psutil
    from matrixscan.perf import benchmark
    proc = _detached_sleep()
    seen = []

    def fake_suite(job, label, base, span, quick=False):
        seen.append(proc.status())
        return {k: {"value": 10.0, "runs": [10.0], "spread": 0.0} for k in benchmark.TESTS}

    monkeypatch.setattr(benchmark, "run_suite", fake_suite)
    monkeypatch.setattr(Job, "sleep", lambda self, s: None)
    try:
        result = benchmark.run(Job("benchmark", {}), names=[proc.name()], quick=True)
        assert seen[0] != psutil.STATUS_STOPPED          # fase 1: activo
        assert seen[1] == psutil.STATUS_STOPPED          # fase 2: en pausa
        assert proc.status() != psutil.STATUS_STOPPED    # al final: reanudado
        assert result["paused_procs"][0]["name"] == proc.name()
        assert not benchmark._recovery_path().exists()
    finally:
        proc.kill()


def test_recovery_after_crash():
    import json as _json
    import psutil
    from matrixscan.perf import benchmark
    proc = _detached_sleep()
    other = _detached_sleep()
    try:
        proc.suspend()
        other.suspend()
        # 'other' simula un PID reutilizado por otro proceso: no debe tocarse
        benchmark._recovery_path().write_text(_json.dumps([
            {"pid": proc.pid, "created": proc.create_time()},
            {"pid": other.pid, "created": other.create_time() - 100},
        ]))
        assert benchmark.recover_suspended() == 1
        assert proc.status() != psutil.STATUS_STOPPED
        assert other.status() == psutil.STATUS_STOPPED
        assert not benchmark._recovery_path().exists()
    finally:
        proc.kill()
        other.kill()
