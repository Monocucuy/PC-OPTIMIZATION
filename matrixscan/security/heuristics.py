"""Heurística de comportamiento sospechoso para procesos y entradas de arranque.

Esto NO es un antivirus: marca señales que el malware suele dar (ubicación, firma, nombre,
línea de comandos). Un resultado 'alto' merece revisión y una consulta a VirusTotal/Defender.
"""
from __future__ import annotations

import ntpath
import re

SYSTEM32_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "spoolsv.exe", "taskhostw.exe", "dwm.exe", "lsm.exe", "conhost.exe", "rundll32.exe", "dllhost.exe",
    "ctfmon.exe", "sihost.exe", "fontdrvhost.exe", "searchindexer.exe", "runtimebroker.exe",
    "taskmgr.exe", "wuauclt.exe", "audiodg.exe", "lsaiso.exe",
}
WINDIR_NAMES = {"explorer.exe"}
_TYPO_TARGETS = sorted(SYSTEM32_NAMES | WINDIR_NAMES)
# Nombres legítimos a distancia 1 de un proceso del sistema
_TYPO_SAFE = {"taskhost.exe", "taskhostex.exe", "service.exe"}

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
                  "onenote.exe", "acrord32.exe", "acrobat.exe"}
SCRIPT_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}

_LOCATIONS = [
    (re.compile(r"\\\$recycle\.bin\\"), 4, "Se ejecuta desde la Papelera de reciclaje"),
    (re.compile(r"\\appdata\\local\\temp\\"), 3, "Se ejecuta desde la carpeta Temp"),
    (re.compile(r"\\windows\\temp\\"), 3, "Se ejecuta desde la carpeta Temp de Windows"),
    (re.compile(r"\\users\\public\\"), 2, "Se ejecuta desde la carpeta Pública"),
    (re.compile(r"\\downloads\\"), 2, "Se ejecuta desde Descargas"),
    (re.compile(r"\\windows\\fonts\\|\\windows\\debug\\|\\windows\\tasks\\"), 3,
     "Ejecutable en una carpeta de Windows donde no debería haber programas"),
]
_LOOSE_ROOTS = [
    (re.compile(r"\\appdata\\roaming$"), "Ejecutable suelto en la raíz de AppData\\Roaming"),
    (re.compile(r"\\appdata\\local$"), "Ejecutable suelto en la raíz de AppData\\Local"),
    (re.compile(r"^[a-z]:\\programdata$"), "Ejecutable suelto en la raíz de ProgramData"),
]
_CMDLINE = [
    (re.compile(r"(powershell|pwsh)(\.exe)?\"?\s.*\s-(e|ec|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{24,}", re.I | re.S),
     4, "PowerShell con comando codificado (oculta lo que ejecuta)"),
    (re.compile(r"(iex|invoke-expression).*(downloadstring|net\.webclient|invoke-webrequest|iwr\s|irm\s)|"
                r"(downloadstring|net\.webclient|invoke-webrequest|iwr\s|irm\s).*(iex|invoke-expression)", re.I | re.S),
     4, "Descarga y ejecuta código desde internet"),
    (re.compile(r"-w(indowstyle)?\s+h(idden)?\b", re.I), 2, "Se ejecuta con la ventana oculta"),
    (re.compile(r"mshta(\.exe)?\"?\s+.*(https?:|javascript:|vbscript:)", re.I), 4, "mshta ejecutando script remoto"),
    (re.compile(r"certutil(\.exe)?\"?\s+.*-(urlcache|decode|decodehex)", re.I), 4, "certutil usado para descargar o decodificar"),
    (re.compile(r"bitsadmin(\.exe)?\"?\s+.*/transfer", re.I), 3, "bitsadmin descargando archivos"),
    (re.compile(r"regsvr32(\.exe)?\"?\s+.*/i:\s*https?:", re.I), 4, "regsvr32 cargando código remoto"),
    (re.compile(r"rundll32(\.exe)?\"?\s+.*(javascript:|\\appdata\\|\\temp\\|\\users\\public\\)", re.I), 3,
     "rundll32 cargando código desde una ubicación inusual"),
    (re.compile(r"(wscript|cscript)(\.exe)?\"?\s+.*(\\temp\\|\\downloads\\|\\appdata\\|\\users\\public\\)", re.I), 3,
     "Script de Windows ejecutándose desde una carpeta temporal"),
    (re.compile(r"vssadmin(\.exe)?\"?\s+.*delete\s+shadows|wmic(\.exe)?\"?\s+.*shadowcopy\s+delete|"
                r"wbadmin(\.exe)?\"?\s+.*delete\s+catalog", re.I), 6,
     "Borra las copias de seguridad de Windows (típico de ransomware)"),
    (re.compile(r"bcdedit(\.exe)?\"?\s+.*recoveryenabled\s+no", re.I), 5, "Desactiva la recuperación de Windows"),
    (re.compile(r"add-mppreference\s+.*-exclusion|set-mppreference\s+.*-disable", re.I), 5,
     "Intenta desactivar o excluir rutas de Windows Defender"),
]
_DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\.(exe|scr|com|bat|cmd|pif|vbs|js)$", re.I)

LEVELS = [(6, "alto"), (4, "medio"), (2, "bajo"), (0, "ok")]


def level_for(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "ok"


def _distance(a: str, b: str) -> int:
    """Distancia de Damerau-Levenshtein (versión de transposiciones adyacentes)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def typosquat_of(name: str) -> str | None:
    """Detecta nombres que imitan a un proceso de Windows (svch0st.exe, scvhost.exe...)."""
    low = name.lower()
    if low in SYSTEM32_NAMES or low in WINDIR_NAMES or low in _TYPO_SAFE or len(low) < 8:
        return None
    swapped = low.replace("0", "o").replace("1", "l")
    for target in _TYPO_TARGETS:
        if swapped == target or _distance(low, target) == 1:
            return target
    return None


def _expected_dirs(windir: str) -> tuple[set[str], set[str]]:
    w = windir.lower().rstrip("\\")
    sys_dirs = {w + "\\system32", w + "\\syswow64"}
    return sys_dirs, {w}


def assess(path: str | None, name: str, cmdline: str = "", signature: dict | None = None,
           parent_name: str = "", cpu_percent: float = 0.0, has_internet: bool = False,
           exists: bool | None = None, windir: str = r"C:\Windows") -> dict:
    """Evalúa un ejecutable. Devuelve {'score', 'level', 'reasons': [{'code','text','weight'}]}."""
    reasons: list[dict] = []

    def add(code: str, weight: int, text: str) -> None:
        reasons.append({"code": code, "weight": weight, "text": text})

    name_low = (name or "").lower()
    path_low = (path or "").lower().replace("/", "\\")
    folder = ntpath.dirname(path_low)
    sig_status = (signature or {}).get("status")
    signer = (signature or {}).get("signer") or ""

    if path_low:
        for rx, weight, text in _LOCATIONS:
            if rx.search(path_low):
                add("location", weight, text)
                break
        for rx, text in _LOOSE_ROOTS:
            if rx.search(folder):
                add("loose_root", 2, text)
                break
        sys_dirs, win_dirs = _expected_dirs(windir)
        if name_low in SYSTEM32_NAMES and folder not in sys_dirs and "\\winsxs\\" not in path_low:
            add("masquerade", 6, f"Se llama como un proceso de Windows ({name}) pero NO está en System32")
        elif name_low in WINDIR_NAMES and folder not in win_dirs:
            add("masquerade", 6, f"Se llama como un proceso de Windows ({name}) pero NO está en la carpeta de Windows")
        if exists is False:
            add("missing", 3, "El ejecutable ya no existe en el disco pero sigue activo o registrado")

    target = typosquat_of(name_low)
    if target:
        add("typosquat", 5, f"Nombre casi idéntico a '{target}' (posible imitación)")
    if _DOUBLE_EXT.search(name_low):
        add("double_ext", 4, "Doble extensión para parecer un documento (ej. factura.pdf.exe)")
    elif name_low.endswith(".scr"):
        add("screensaver", 2, "Protector de pantalla (.scr) ejecutándose como programa")

    if cmdline:
        hits = 0
        for rx, weight, text in _CMDLINE:
            if rx.search(cmdline):
                add("cmdline", weight, text)
                hits += 1
                if hits >= 3:
                    break

    if parent_name.lower() in OFFICE_PARENTS and name_low in SCRIPT_HOSTS:
        add("office_child", 4, f"Abierto por {parent_name}: los documentos no deberían lanzar consolas o scripts")

    if sig_status:
        if sig_status == "NotSigned":
            add("unsigned", 2, "Sin firma digital")
        elif sig_status in ("HashMismatch", "NotTrusted", "Incompatible"):
            add("bad_signature", 4, f"Firma digital inválida ({sig_status})")

    if cpu_percent >= 25:
        add("cpu", 1, f"Consumo de CPU alto ({cpu_percent:.0f}%)")
    if has_internet and sig_status == "NotSigned":
        add("network", 1, "Conectado a internet sin firma digital")

    score = sum(r["weight"] for r in reasons)
    if sig_status == "Valid" and score:
        trust = 3 if "microsoft" in signer.lower() else 2
        # Una firma válida reduce el riesgo, pero no anula imitaciones de nombre ni comandos maliciosos
        if not any(r["code"] in ("masquerade", "cmdline", "office_child") for r in reasons):
            score = max(0, score - trust)
    return {"score": score, "level": level_for(score), "reasons": reasons}
