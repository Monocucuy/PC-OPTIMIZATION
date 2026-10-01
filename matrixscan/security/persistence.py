"""Programas que arrancan solos: claves Run, carpetas de Inicio y tareas programadas.

Es donde el malware se instala para sobrevivir a un reinicio, y también donde se acumulan
programas que ralentizan el arranque.
"""
from __future__ import annotations

import ntpath
import os

from ..jobs import Job
from ..util import IS_WINDOWS, as_list, powershell_json, ps_quote
from ..winapi import reg_values
from . import signatures
from .heuristics import SCRIPT_HOSTS, assess, level_for

RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0x0100),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0x0100),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0x0200),
]
APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"

_TASKS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = foreach ($t in Get-ScheduledTask) {
  if ($t.State -eq 'Disabled') { continue }
  $acts = @()
  foreach ($a in $t.Actions) { if ($a.Execute) { $acts += [pscustomobject]@{ e = [string]$a.Execute; g = [string]$a.Arguments } } }
  if ($acts.Count -eq 0) { continue }
  [pscustomobject]@{ n = [string]$t.TaskName; p = [string]$t.TaskPath; s = [string]$t.State; a = $acts }
}
ConvertTo-Json -InputObject @($r) -Compress -Depth 4
"""

_LNK_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$sh = New-Object -ComObject WScript.Shell
$r = foreach ($f in @({files})) {
  $l = $sh.CreateShortcut($f)
  [pscustomobject]@{ f = $f; t = [string]$l.TargetPath; g = [string]$l.Arguments }
}
ConvertTo-Json -InputObject @($r) -Compress
"""


def split_command(command: str) -> tuple[str, str]:
    """Separa '"C:\\ruta\\app.exe" --args' en (ejecutable, argumentos)."""
    command = os.path.expandvars((command or "").strip())
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 0:
            return command[1:end], command[end + 1:].strip()
        return command[1:], ""
    parts = command.split(" ")
    # Rutas sin comillas con espacios: probar el prefijo más largo que exista
    for i in range(len(parts), 0, -1):
        cand = " ".join(parts[:i])
        for c in (cand, cand + ".exe"):
            if os.path.isfile(c):
                return c, " ".join(parts[i:])
    return parts[0], " ".join(parts[1:])


def script_target(exe: str, args: str) -> str | None:
    """Si el ejecutable es un intérprete (rundll32, wscript...), devuelve el archivo que carga."""
    if ntpath.basename(exe).lower() not in SCRIPT_HOSTS:
        return None
    for token in args.replace(",", " ").split():
        token = token.strip('"')
        if ("\\" in token or "/" in token) and ntpath.splitext(token)[1].lower() in (
                ".dll", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".exe"):
            return os.path.expandvars(token)
    return None


def resolve_exe(exe: str) -> str:
    """Convierte 'cmd.exe' en su ruta completa si no trae carpeta."""
    if not exe or ntpath.dirname(exe) or not IS_WINDOWS:
        return exe
    for folder in (os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"),
                   os.environ.get("SystemRoot", r"C:\Windows")):
        cand = os.path.join(folder, exe if exe.lower().endswith(".exe") else exe + ".exe")
        if os.path.isfile(cand):
            return cand
    return exe


def _approved_state(hive, kind: str, name: str) -> bool | None:
    """StartupApproved: primer byte 0x02/0x06 = habilitado, 0x03/0x07 = deshabilitado."""
    for vname, data, _ in reg_values(hive, rf"{APPROVED}\{kind}"):
        if vname.lower() == name.lower() and isinstance(data, (bytes, bytearray)) and data:
            return data[0] in (0x02, 0x06)
    return None


def _registry_entries() -> list[dict]:
    import winreg
    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    out = []
    for hive_name, key, view in RUN_KEYS:
        hive = hives[hive_name]
        for name, value, _ in reg_values(hive, key, view):
            if not isinstance(value, str) or not value.strip():
                continue
            kind = "Run32" if view == 0x0200 else "Run"
            enabled = _approved_state(hive, kind, name)
            out.append({"source": f"Registro {hive_name}\\…\\{key.rsplit(chr(92), 1)[-1]}", "name": name,
                        "command": value, "enabled": True if enabled is None else enabled})
    return out


def _startup_folder_entries() -> list[dict]:
    folders = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"),
    ]
    files = []
    for folder in folders:
        try:
            files += [e.path for e in os.scandir(folder) if e.is_file() and e.name.lower() != "desktop.ini"]
        except OSError:
            continue
    out = []
    lnks = [f for f in files if f.lower().endswith(".lnk")]
    resolved = {}
    if lnks:
        data = powershell_json(_LNK_SCRIPT.replace("{files}", ",".join(ps_quote(f) for f in lnks)), timeout=30)
        resolved = {row.get("f"): row for row in as_list(data) if isinstance(row, dict)}
    import winreg
    for f in files:
        row = resolved.get(f)
        command = f'"{row["t"]}" {row.get("g", "")}'.strip() if row and row.get("t") else f'"{f}"'
        enabled = _approved_state(winreg.HKEY_CURRENT_USER, "StartupFolder", os.path.basename(f))
        out.append({"source": "Carpeta Inicio", "name": os.path.basename(f), "command": command,
                    "enabled": True if enabled is None else enabled})
    return out


def _task_entries() -> list[dict]:
    data = powershell_json(_TASKS_SCRIPT, timeout=90)
    out = []
    for t in as_list(data):
        if not isinstance(t, dict):
            continue
        for act in as_list(t.get("a")):
            if not isinstance(act, dict) or not act.get("e"):
                continue
            exe = act["e"]
            command = (f'"{exe}" ' if not exe.startswith('"') else exe + " ") + (act.get("g") or "")
            out.append({"source": "Tarea programada", "name": (t.get("p") or "\\") + (t.get("n") or "?"),
                        "command": command.strip(), "enabled": t.get("s") != "Disabled",
                        "microsoft": (t.get("p") or "").lower().startswith("\\microsoft\\")})
    return out


def scan(job: Job) -> dict:
    if not IS_WINDOWS:
        job.log("> El análisis de arranque solo está disponible en Windows.")
        return {"supported": False, "entries": []}
    job.log("> Leyendo claves Run del registro...")
    job.set_progress(0.05, "Registro: claves Run")
    entries = _registry_entries()
    job.log("> Leyendo carpetas de Inicio...")
    job.set_progress(0.15, "Carpetas de Inicio")
    entries += _startup_folder_entries()
    job.check()
    job.log("> Leyendo tareas programadas (puede tardar unos segundos)...")
    job.set_progress(0.3, "Tareas programadas")
    entries += _task_entries()
    job.check()

    for e in entries:
        exe, args = split_command(e["command"])
        exe = resolve_exe(exe)
        e["exe"] = exe
        e["target"] = script_target(exe, args)
    paths = [e["exe"] for e in entries if e["exe"]] + [e["target"] for e in entries if e["target"]]
    job.log(f"> Verificando firmas de {len(set(paths))} ejecutables...")
    job.set_progress(0.55, "Verificando firmas digitales")
    sigs = signatures.check([p for p in paths if os.path.isfile(p)])
    windir = os.environ.get("SystemRoot", r"C:\Windows")

    results = []
    for e in entries:
        exe, target = e["exe"], e["target"]
        check_path = target or exe
        sig = sigs.get(os.path.normcase(check_path)) if check_path else None
        verdict = assess(check_path, ntpath.basename(check_path or ""), cmdline=e["command"], signature=sig,
                         exists=os.path.exists(check_path) if check_path and ntpath.dirname(check_path) else None,
                         windir=windir)
        reasons = verdict["reasons"]
        score = verdict["score"]
        if any(r["code"] == "missing" for r in reasons):
            for r in reasons:
                if r["code"] == "missing":
                    r["text"] = "Apunta a un archivo que ya no existe (resto de un programa desinstalado)"
                    r["weight"] = 1
            score = sum(r["weight"] for r in reasons)
        if e.get("microsoft") and score < 2:
            continue  # cientos de tareas internas de Windows: solo se muestran si son sospechosas
        results.append({
            "source": e["source"], "name": e["name"], "command": e["command"][:500], "path": check_path,
            "enabled": e["enabled"], "signer": (sig or {}).get("signer", ""),
            "sig_status": (sig or {}).get("status", ""), "score": score, "level": level_for(score),
            "reasons": reasons,
        })

    order = {"alto": 3, "medio": 2, "bajo": 1, "ok": 0}
    results.sort(key=lambda r: (order[r["level"]], r["score"], r["enabled"]), reverse=True)
    counts = {lvl: sum(1 for r in results if r["level"] == lvl) for lvl in order}
    active = sum(1 for r in results if r["enabled"] and r["source"] != "Tarea programada")
    job.log(f"> {len(results)} entradas de arranque ({active} programas al iniciar sesión). "
            f"Sospechosas: {counts['alto']} alto · {counts['medio']} medio")
    return {"supported": True, "entries": results, "counts": counts, "startup_programs": active}
