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
