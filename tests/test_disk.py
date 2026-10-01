import os
import struct
import time

import pytest

from matrixscan.disk import duplicates, large_files, programs
from matrixscan.jobs import Job
from matrixscan.util import dir_summary, unique_roots


@pytest.fixture
def job():
    return Job("test", {})


def write(path, data: bytes, age_days: float = 0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    if age_days:
        t = time.time() - age_days * 86400
        os.utime(path, (t, t))


def test_duplicates_by_content_not_name(tmp_path, job):
    blob = os.urandom(300_000)
    write(tmp_path / "a" / "foto.jpg", blob)
    write(tmp_path / "b" / "copia de foto.jpg", blob)
    write(tmp_path / "c" / "otra.jpg", blob[:-1] + b"X")  # mismo tamaño, contenido distinto
    r = duplicates.scan(job, [str(tmp_path)], min_mb=0.1, skip_appdata=False)
    assert r["group_count"] == 1
    g = r["groups"][0]
    assert g["count"] == 2 and g["wasted"] == 300_000


def test_duplicates_overlapping_roots_not_self_matched(tmp_path, job):
    write(tmp_path / "sub" / "unico.bin", os.urandom(200_000))
    r = duplicates.scan(job, [str(tmp_path), str(tmp_path / "sub")], min_mb=0.1, skip_appdata=False)
    assert r["group_count"] == 0


def test_large_unused_files(tmp_path, job):
    write(tmp_path / "viejo.iso", b"\0" * 2_000_000, age_days=400)
    write(tmp_path / "nuevo.mkv", b"\0" * 2_000_000)
    write(tmp_path / "chico.zip", b"\0" * 1000, age_days=400)
    r = large_files.scan(job, [str(tmp_path)], min_mb=1, days=180)
    names = [os.path.basename(f["path"]) for f in r["files"]]
    assert names == ["viejo.iso"]
    assert r["files"][0]["kind"] == "Imagen de disco"
    assert r["files"][0]["days_unused"] >= 399


def test_unique_roots(tmp_path):
    (tmp_path / "x" / "y").mkdir(parents=True)
    roots = unique_roots([str(tmp_path / "x" / "y"), str(tmp_path / "x"), str(tmp_path / "x"), "/no/existe"])
    assert roots == [str(tmp_path / "x")]


def test_dir_summary_filters(tmp_path):
    write(tmp_path / "old.exe", b"1" * 500, age_days=60)
    write(tmp_path / "new.exe", b"1" * 500)
    write(tmp_path / "old.txt", b"1" * 500, age_days=60)
    s = dir_summary(str(tmp_path), older_than=time.time() - 30 * 86400, extensions=(".exe",))
    assert s["files"] == 1 and s["size"] == 500
    assert dir_summary(str(tmp_path), top_n=0)["files"] == 3


def test_userassist_value_parsing():
    import codecs
    ft = int((1_700_000_000 * 10_000_000) + 116444736000000000)
    data = bytearray(72)
    struct.pack_into("<I", data, 4, 7)
    struct.pack_into("<Q", data, 60, ft)
    name = codecs.encode("{6D809377-6AF0-444B-8957-A3773F02200E}\\Blender Foundation\\blender.exe", "rot_13")
    path, count, last = programs.parse_userassist_value(name, bytes(data))
    assert path.endswith(r"\Blender Foundation\blender.exe") and path.startswith("%ProgramFiles%")
    assert count == 7 and abs(last - 1_700_000_000) < 1


def test_program_usage_matching_and_status():
    now = time.time()
    prog = {"name": "Blender 4.2"}
    prefetch = {"BLENDER.EXE": now - 3 * 86400}
    last, src = programs.match_usage(prog, ["blender.exe", "unins000.exe"], prefetch, {}, {})
    assert src == "Prefetch" and programs.classify(last, True, now) == "en_uso"
    # el desinstalador no cuenta como uso
    last, _ = programs.match_usage(prog, ["unins000.exe"], {"UNINS000.EXE": now}, {}, {})
    assert last is None
    assert programs.classify(None, True) == "sin_registro"
    assert programs.classify(None, False) == "desconocido"
    assert programs.classify(now - 400 * 86400, True, now) == "sin_uso"
