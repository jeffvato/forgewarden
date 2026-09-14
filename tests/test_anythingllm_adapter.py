import json
from pathlib import Path
import subprocess
import pytest
from swarm.anythingllm_adapter import AnythingLLMConfig, AnythingLLMError, AnythingLLMReviewer

JOB = "phase2a-" + "a" * 24
COMMIT = "b" * 40

def approval():
    return {"job_id":JOB,"reviewed_commit":COMMIT,"verdict":"APPROVE","risk":"LOW","blocking_findings":[],"non_blocking_notes":[],"tests_missing":[],"reasoning_summary":"bounded","proposed_rules":[]}

def test_bridge_invocation_is_fixed_bounded_and_exact(monkeypatch):
    seen={}
    def runner(command, **kwargs):
        seen.update(command=command, kwargs=kwargs)
        return subprocess.CompletedProcess(command,0,json.dumps(approval()).encode(),b"")
    result=AnythingLLMReviewer(AnythingLLMConfig(),runner=runner).run(None,JOB,COMMIT,"exact patch")
    assert result["verdict"]=="APPROVE"
    assert seen["command"][:6]==[r"/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe","-NoLogo","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass"]
    assert seen["command"][-4:]==["-Workspace","n8n","-SessionId",JOB]
    assert seen["command"][7].startswith("C:\\") and seen["command"][7].endswith("anythingllm-review-bridge.ps1")
    assert b"under 700 output tokens" in seen["kwargs"]["input"]
    assert b"exact patch" in seen["kwargs"]["input"]
    assert set(seen["kwargs"]["env"])=={"SystemRoot","WINDIR"}

@pytest.mark.parametrize("result",[
    subprocess.CompletedProcess([],1,b"",b"secret value"),
    subprocess.CompletedProcess([],0,b"not-json",b""),
    subprocess.CompletedProcess([],0,json.dumps({**approval(),"reviewed_commit":"c"*40}).encode(),b""),
])
def test_failure_output_and_binding_fail_closed(result):
    with pytest.raises(Exception):
        AnythingLLMReviewer(AnythingLLMConfig(),runner=lambda *_a,**_k:result).run(None,JOB,COMMIT,"review")

def test_configuration_and_prompt_bounds():
    with pytest.raises(AnythingLLMError): AnythingLLMConfig(workspace="../escape")
    with pytest.raises(AnythingLLMError): AnythingLLMReviewer(AnythingLLMConfig()).run(None,JOB,COMMIT,"x"*48001)
    with pytest.raises(AnythingLLMError): AnythingLLMReviewer(AnythingLLMConfig()).run(None,JOB,COMMIT,"x"*47000)

def test_markdown_json_fence_is_accepted_without_relaxing_schema():
    fenced = ("```json\n" + json.dumps(approval()) + "\n```").encode()
    result = AnythingLLMReviewer(AnythingLLMConfig(), runner=lambda *_a, **_k: subprocess.CompletedProcess([], 0, fenced, b"")).run(None, JOB, COMMIT, "review")
    assert result["reviewed_commit"] == COMMIT

def test_invalid_json_inside_markdown_fence_is_rejected():
    output = b"```json\n{not-json}\n```"
    reviewer = AnythingLLMReviewer(
        AnythingLLMConfig(),
        runner=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, b""),
    )
    with pytest.raises(AnythingLLMError, match="invalid JSON"):
        reviewer.run(object(), JOB, COMMIT, "review")

def test_fence_with_extra_text_is_rejected():
    output = b"preface\n```json\n{}\n```"
    reviewer = AnythingLLMReviewer(
        AnythingLLMConfig(),
        runner=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, b""),
    )
    with pytest.raises(AnythingLLMError, match="invalid JSON"):
        reviewer.run(object(), JOB, COMMIT, "review")

def test_missing_closing_fence_is_rejected_explicitly():
    output = b"```json\n{}"
    reviewer = AnythingLLMReviewer(
        AnythingLLMConfig(),
        runner=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, output, b""),
    )
    with pytest.raises(AnythingLLMError, match="incomplete JSON fence"):
        reviewer.run(object(), JOB, COMMIT, "review")

def test_windows_bridge_requires_exact_firewall_protection_for_wildcard_listener():
    bridge = (Path(__file__).parents[1] / "scripts" / "anythingllm-review-bridge.ps1").read_text()
    assert "ForgeWarden - Block AnythingLLM network access" in bridge
    assert "Get-NetFirewallApplicationFilter" in bridge
    assert "Test-AnythingLLMFirewallBoundary $bindings $program" in bridge
    assert "$firewallProtected -and $_.LocalAddress -in @('0.0.0.0','::')" in bridge

def test_windows_bridge_imports_builtin_dpapi_module_by_fixed_path():
    bridge = (Path(__file__).parents[1] / "scripts" / "anythingllm-review-bridge.ps1").read_text()
    assert "Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security" in bridge
    assert "built-in DPAPI module is unavailable" in bridge
    assert "Import-Module -Name $securityModule -ErrorAction Stop" in bridge

def test_windows_bridge_firewall_boundary_cases_execute_fail_closed():
    powershell = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    if not powershell.is_file():
        pytest.skip("Windows PowerShell interop is unavailable")
    bridge = Path(__file__).parents[1] / "scripts" / "anythingllm-review-bridge.ps1"
    completed = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(bridge).replace("/mnt/c/", "C:/"), "-Workspace", "n8n", "-SessionId", JOB,
         "-BoundarySelfTest"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"},
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "BOUNDARY_SELF_TEST_OK"
