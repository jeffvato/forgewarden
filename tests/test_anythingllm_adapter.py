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
    assert seen["command"][:6]==["powershell.exe","-NoLogo","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass"]
    assert seen["command"][-4:]==["-Workspace","n8n","-SessionId",JOB]
    assert seen["command"][7].startswith("C:\\") and seen["command"][7].endswith("anythingllm-review-bridge.ps1")
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
