from matrixscan.security import heuristics as h
from matrixscan.security.defender import decode_product_state
from matrixscan.security.persistence import script_target, split_command
from matrixscan.security.signatures import signer_name
from matrixscan.security.virustotal import parse_report

WIN = r"C:\Windows"


def codes(result):
    return {r["code"] for r in result["reasons"]}


def test_legit_system_process_is_clean():
    r = h.assess(r"C:\Windows\System32\svchost.exe", "svchost.exe",
                 signature={"status": "Valid", "signer": "Microsoft Windows"}, windir=WIN)
    assert r["level"] == "ok" and r["score"] == 0


def test_masquerading_system_name_is_high():
    r = h.assess(r"C:\Users\Juan\AppData\Roaming\svchost.exe", "svchost.exe",
                 signature={"status": "NotSigned"}, windir=WIN)
    assert "masquerade" in codes(r)
    assert r["level"] == "alto"


def test_typosquat_from_temp_is_high():
    r = h.assess(r"C:\Users\Juan\AppData\Local\Temp\svch0st.exe", "svch0st.exe",
                 signature={"status": "NotSigned"}, cpu_percent=40, windir=WIN)
    assert {"typosquat", "location", "unsigned", "cpu"} <= codes(r)
    assert r["level"] == "alto"


def test_typosquat_detection():
    assert h.typosquat_of("scvhost.exe") == "svchost.exe"
    assert h.typosquat_of("svch0st.exe") == "svchost.exe"
    assert h.typosquat_of("explorer.exe") is None
    assert h.typosquat_of("taskhost.exe") is None  # nombre legítimo antiguo
    assert h.typosquat_of("chrome.exe") is None


def test_encoded_powershell_is_flagged_even_if_signed():
    cmd = "powershell.exe -NoP -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA="
    r = h.assess(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe", cmdline=cmd,
                 signature={"status": "Valid", "signer": "Microsoft Corporation"}, windir=WIN)
    assert "cmdline" in codes(r)
    assert r["score"] >= 4  # la firma de Microsoft no anula un comando ofuscado


def test_ransomware_shadow_delete():
    r = h.assess(r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe",
                 cmdline="vssadmin.exe delete shadows /all /quiet", windir=WIN)
    assert r["level"] == "alto"


def test_double_extension():
    r = h.assess(r"C:\Users\Juan\Desktop\factura.pdf.exe", "factura.pdf.exe", windir=WIN)
    assert "double_ext" in codes(r)


def test_office_spawning_shell():
    r = h.assess(r"C:\Windows\System32\cmd.exe", "cmd.exe", parent_name="WINWORD.EXE", windir=WIN)
    assert "office_child" in codes(r)


def test_signed_app_in_downloads_is_reduced():
    r = h.assess(r"C:\Users\Juan\Downloads\SteamSetup.exe", "SteamSetup.exe",
                 signature={"status": "Valid", "signer": "Valve Corp."}, windir=WIN)
    assert r["level"] == "ok"


def test_split_command_variants():
    assert split_command('"C:\\Program Files\\App\\app.exe" --min') == ("C:\\Program Files\\App\\app.exe", "--min")
    exe, args = split_command("rundll32.exe C:\\Users\\x\\AppData\\evil.dll,Start")
    assert exe == "rundll32.exe"
    assert script_target(exe, args) == "C:\\Users\\x\\AppData\\evil.dll"
    assert script_target("C:\\app.exe", "--x") is None


def test_signer_name():
    assert signer_name("CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, C=US") == "Microsoft Corporation"
    assert signer_name('CN="Valve Corp.", O="Valve Corp.", C=US') == "Valve Corp."
    assert signer_name("CN=Solo Nombre") == "Solo Nombre"


def test_product_state_decoding():
    assert decode_product_state(397568) == {"enabled": True, "up_to_date": True}   # 0x061100
    assert decode_product_state(393472) == {"enabled": False, "up_to_date": True}  # 0x060100
    assert decode_product_state(397584)["up_to_date"] is False                     # 0x061110


def test_virustotal_report_parsing():
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 41, "suspicious": 2, "undetected": 25, "harmless": 0, "timeout": 4},
        "popular_threat_classification": {"suggested_threat_label": "trojan.coinminer/xmrig"},
        "meaningful_name": "svch0st.exe"}}}
    r = parse_report(payload)
    assert r["verdict"] == "malicioso" and r["malicious"] == 41 and r["engines"] == 72
    clean = parse_report({"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 70}}}})
    assert clean["verdict"] == "limpio"


# ---------------------------------------------------------------- regresiones de la primera ejecución en Windows

def test_signature_script_never_uses_get_content():
    # Get-Content hace que ConvertTo-Json (PS 5.1) serialice cada ruta como objeto, no como texto
    from matrixscan.security import signatures
    assert "Get-Content" not in signatures._SCRIPT
    assert "[string]$line" in signatures._SCRIPT


def test_signatures_accept_paths_serialized_as_objects(tmp_path, monkeypatch):
    import os
    from matrixscan.security import signatures
    exe = tmp_path / "app.exe"
    exe.write_bytes(b"MZ")
    rows = [
        {"p": {"value": str(exe), "PSPath": "Microsoft.PowerShell.Core\\FileSystem::" + str(exe), "ReadCount": 1},
         "s": "NotSigned", "c": ""},
        {"p": str(exe), "s": "NotSigned", "c": ""},
        {"p": None, "s": "NotSigned", "c": ""},
        None,
    ]
    monkeypatch.setattr(signatures, "IS_WINDOWS", True)
    monkeypatch.setattr(signatures, "powershell_json", lambda *a, **k: rows)
    signatures._cache.clear()
    result = signatures.check([str(exe)])
    assert result == {os.path.normcase(str(exe)): {"status": "NotSigned", "signer": ""}}


def test_wmi_fallback_fills_missing_paths():
    from types import SimpleNamespace
    from matrixscan.security.processes import merge_cim
    procs = [
        SimpleNamespace(pid=10, info={"exe": None, "cmdline": None, "ppid": None}),
        SimpleNamespace(pid=11, info={"exe": r"C:\keep.exe", "cmdline": ["keep"], "ppid": 1}),
        SimpleNamespace(pid=12, info={"exe": None, "cmdline": None, "ppid": None}),
    ]
    cim = {
        10: {"exe": r"C:\Windows\System32\svchost.exe", "cmd": "svchost.exe -k netsvcs", "ppid": 4},
        11: {"exe": r"C:\other.exe", "cmd": "other", "ppid": 9},
    }
    assert merge_cim(procs, cim) == 1
    assert procs[0].info == {"exe": r"C:\Windows\System32\svchost.exe", "cmdline": ["svchost.exe -k netsvcs"], "ppid": 4}
    assert procs[1].info["exe"] == r"C:\keep.exe"      # lo que psutil sí obtuvo no se pisa
    assert procs[2].info["exe"] is None                # sin datos en WMI: queda igual


def test_diagnose_missing_reports_real_cause():
    from matrixscan.security.processes import diagnose_missing

    class Denied:
        def exe(self):
            raise PermissionError("acceso denegado")

    class Fine:
        def exe(self):
            return "x"

    text = diagnose_missing([Denied(), Denied(), Fine()])
    assert "PermissionError×2" in text and "ok al reintentar×1" in text and "acceso denegado" in text


def test_defender_age_sentinels_become_unknown():
    from matrixscan.security.defender import clean_ages
    # equipo real: Defender apagado (otro antivirus al mando) devolvía 65535 días
    data = clean_ages({"sig_age_days": 65535, "quick_scan_age_days": 4294967295, "full_scan_age_days": -1})
    assert data == {"sig_age_days": None, "quick_scan_age_days": None, "full_scan_age_days": None}
    ok = clean_ages({"sig_age_days": 0, "quick_scan_age_days": 3, "full_scan_age_days": 45})
    assert ok == {"sig_age_days": 0, "quick_scan_age_days": 3, "full_scan_age_days": 45}
    assert clean_ages({"sig_age_days": None})["sig_age_days"] is None
