"""Safety boundaries and the optional Phase-2 generator."""
from __future__ import annotations

import pytest
from _srcutil import code_only

from rvbench.adapters.windows_lab import SAFETY_FLAG, RealEndpointSafetyError, WindowsLabAdapter
from rvbench.remediation.generator import DEFAULT_MODEL, GeneratorConfig, LLMDisabled, RemediationGenerator
from rvbench.simulator.engine import RemediationOpError


def test_real_windows_adapter_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv(SAFETY_FLAG, raising=False)
    with pytest.raises(RealEndpointSafetyError):
        WindowsLabAdapter()


def test_real_windows_adapter_is_still_unimplemented_with_the_flag(monkeypatch):
    monkeypatch.setenv(SAFETY_FLAG, "1")
    with pytest.raises(NotImplementedError):
        WindowsLabAdapter()


def test_llm_generation_is_off_without_env(monkeypatch):
    for var in ("RVBENCH_LLM_ENABLED", "RVBENCH_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    gen = RemediationGenerator(GeneratorConfig.from_env({}))
    assert gen.available is False
    with pytest.raises(LLMDisabled):
        gen.generate(None, {})


def test_llm_config_is_vendor_neutral_and_env_driven():
    cfg = GeneratorConfig.from_env({
        "RVBENCH_LLM_ENABLED": "1",
        "RVBENCH_LLM_API_KEY": "k",
        "RVBENCH_LLM_BASE_URL": "https://example.invalid/v1",
        "RVBENCH_LLM_MODEL": "some/cheap-model",
    })
    assert cfg.enabled and cfg.model == "some/cheap-model"
    assert GeneratorConfig.from_env({}).model == DEFAULT_MODEL


def test_generated_plan_is_schema_validated():
    ops = RemediationGenerator.parse_plan(
        '```json\n{"ops": [{"op": "set_registry", "path": "HKLM\\\\X", "value": 0}]}\n```')
    assert ops[0]["op"] == "set_registry"


def test_generated_shell_commands_are_rejected():
    with pytest.raises(RemediationOpError):
        RemediationGenerator.parse_plan('{"ops": [{"op": "Invoke-Expression"}]}')
    with pytest.raises(RemediationOpError):
        RemediationGenerator.parse_plan('{"ops": "Remove-Item C:\\\\"}')


def test_no_module_shells_out_or_opens_sockets():
    """The benchmark must not be able to touch the host or the network."""
    import pathlib
    import re
    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "rvbench"
    offenders = []
    for path in src.rglob("*.py"):
        # scan executable code only: prose in a docstring may discuss these names
        text = code_only(path.read_text())
        rel = path.relative_to(src).as_posix()
        for token in ("subprocess.Popen", "os.system", "socket.", "shutil.rmtree"):
            if token in text:
                offenders.append(f"{rel}:{token}")
        for token in ("eval", "exec"):
            # word-boundary match, so helpers named _exec() do not trip this
            if re.search(r"(?<![\w.])" + token + r"\(", text):
                offenders.append(f"{rel}:{token}()")
        # urllib is permitted only in the opt-in generator
        if "urllib" in text and rel != "remediation/generator.py":
            offenders.append(f"{rel}:urllib")
        # subprocess is permitted only for reading the git SHA in the runner
        if "import subprocess" in text and rel != "runner.py":
            offenders.append(f"{rel}:subprocess")
    assert offenders == [], offenders
