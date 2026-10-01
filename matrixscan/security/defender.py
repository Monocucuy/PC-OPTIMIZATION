"""Integración con Windows Defender: estado, historial de amenazas y escaneo rápido."""
from __future__ import annotations

import glob
import os
import re
import subprocess
import threading

from ..jobs import Job, JobError
from ..util import CREATE_NO_WINDOW, IS_WINDOWS, as_list, powershell_json

_STATUS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{ available = $false }
$s = Get-MpComputerStatus
if ($s) {
  $o.available = $true
  $o.antivirus = [bool]$s.AntivirusEnabled
  $o.realtime = [bool]$s.RealTimeProtectionEnabled
  $o.service = [bool]$s.AMServiceEnabled
  $o.tamper = [bool]$s.IsTamperProtected
  $o.mode = [string]$s.AMRunningMode
  $o.sig_age_days = [int64]$s.AntivirusSignatureAge
  $o.sig_version = [string]$s.AntivirusSignatureVersion
  $o.sig_updated = $(if ($s.AntivirusSignatureLastUpdated) { $s.AntivirusSignatureLastUpdated.ToString('o') } else { $null })
  $o.quick_scan_age_days = [int64]$s.QuickScanAge
  $o.full_scan_age_days = [int64]$s.FullScanAge
}
$o.products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | ForEach-Object {
  [pscustomobject]@{ name = [string]$_.displayName; state = [int64]$_.productState } })
$thr = @{}
foreach ($t in @(Get-MpThreat)) { $thr[[string]$t.ThreatID] = $t }
$o.threats = @(@(Get-MpThreatDetection) | Sort-Object InitialDetectionTime | Select-Object -Last 50 | ForEach-Object {
  $t = $thr[[string]$_.ThreatID]
  [pscustomobject]@{
    name = $(if ($t) { [string]$t.ThreatName } else { 'ID ' + [string]$_.ThreatID })
    severity = $(if ($t) { [int]$t.SeverityID } else { 0 })
    active = $(if ($t) { [bool]$t.IsActive } else { $false })
    time = $(if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('o') } else { $null })
    resources = @($_.Resources | ForEach-Object { [string]$_ })
    process = [string]$_.ProcessName
    action_ok = [bool]$_.ActionSuccess
  } })
ConvertTo-Json -InputObject ([pscustomobject]$o) -Compress -Depth 5
"""

SEVERITY = {0: "Desconocida", 1: "Baja", 2: "Moderada", 4: "Alta", 5: "Grave"}
NEVER = 4294967295  # Defender usa UInt32.MaxValue cuando nunca se ha ejecutado un escaneo


def decode_product_state(state: int) -> dict:
    """productState de SecurityCenter2: byte medio 0x10 = activo; byte bajo 0x00 = firmas al día."""
    middle = (state >> 8) & 0xFF
    low = state & 0xFF
    return {"enabled": (middle & 0x10) == 0x10, "up_to_date": (low & 0x10) == 0}


def status(job: Job | None = None) -> dict:
    if not IS_WINDOWS:
        if job:
            job.log("> Windows Defender solo existe en Windows.")
        return {"supported": False}
    if job:
        job.log("> Consultando Windows Defender y el Centro de seguridad...")
        job.set_progress(None, "Consultando Defender")
    data = powershell_json(_STATUS_SCRIPT, timeout=60)
    if not isinstance(data, dict):
        raise JobError("No se pudo consultar Windows Defender (PowerShell no respondió).")
    for key in ("quick_scan_age_days", "full_scan_age_days", "sig_age_days"):
        if data.get(key) in (NEVER, -1):
            data[key] = None
    products = []
    for p in as_list(data.get("products")):
        if isinstance(p, dict) and p.get("name"):
            products.append({"name": p["name"], **decode_product_state(int(p.get("state") or 0))})
    data["products"] = products
    threats = []
    for t in as_list(data.get("threats")):
        if isinstance(t, dict):
            t["severity_label"] = SEVERITY.get(t.get("severity") or 0, "Desconocida")
            t["resources"] = [re.sub(r"^\w+:_", "", r) for r in as_list(t.get("resources"))][:5]
            threats.append(t)
    data["threats"] = list(reversed(threats))
    data["supported"] = True
    if job:
        state = "ACTIVO" if data.get("realtime") else "INACTIVO"
        job.log(f"  Protección en tiempo real: {state}")
        job.log(f"  Detecciones registradas: {len(threats)}")
    return data


def _decode(raw: bytes) -> str:
    raw = raw.replace(b"\x00", b"")  # salida UTF-16 en algunas versiones: basta con quitar los NUL
    for enc in ("utf-8", "oem", "mbcs"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1")


def _mpcmdrun() -> str | None:
    platform_dir = os.path.expandvars(r"%ProgramData%\Microsoft\Windows Defender\Platform")

    def version_key(path: str):
        ver = os.path.basename(os.path.dirname(path))
        return [int(x) for x in re.findall(r"\d+", ver)]

    found = sorted(glob.glob(os.path.join(platform_dir, "*", "MpCmdRun.exe")), key=version_key, reverse=True)
    found.append(os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"))
    for path in found:
        if os.path.isfile(path):
            return path
    return None


def quick_scan(job: Job) -> dict:
    if not IS_WINDOWS:
        raise JobError("El escaneo de Defender solo está disponible en Windows.")
    exe = _mpcmdrun()
    if not exe:
        raise JobError("No se encontró MpCmdRun.exe. ¿Windows Defender está desactivado por otro antivirus?")
    job.log("> Lanzando escaneo rápido de Windows Defender (suele tardar de 2 a 10 minutos)...")
    job.set_progress(None, "Defender escaneando: memoria, arranque y ubicaciones críticas")
    proc = subprocess.Popen([exe, "-Scan", "-ScanType", "1"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=CREATE_NO_WINDOW)

    def pump() -> None:
        for raw in proc.stdout:
            line = _decode(raw).strip()
            if line:
                job.log("  " + line)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    while proc.poll() is None:
        if job.cancelled:
            subprocess.run([exe, "-Scan", "-Cancel"], capture_output=True, creationflags=CREATE_NO_WINDOW)
            proc.wait(timeout=30)
            job.check()
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    reader.join(timeout=5)
    code = proc.returncode
    if code == 2:
        job.log("> ¡Defender encontró amenazas! Revisa el historial abajo y la app Seguridad de Windows.")
    elif code == 0:
        job.log("> Escaneo terminado: Defender no encontró amenazas.")
    else:
        job.log(f"> MpCmdRun terminó con código {code}. Si pide permisos, abre MatrixScan como administrador.")
    result = status(job)
    result["scan_exit_code"] = code
    result["scan_found_threats"] = code == 2
    return result
