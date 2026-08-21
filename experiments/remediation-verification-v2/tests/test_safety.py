"""Safety boundaries: no real execution path is reachable during a benchmark run."""
from __future__ import annotations

import os
import re
from pathlib import Path

from _srcutil import code_only

SRC = Path(__file__).resolve().parents[1] / "src" / "rv2"


def test_no_module_shells_out_opens_sockets_or_evals():
    offenders = []
    for path in SRC.rglob("*.py"):
        code = code_only(path.read_text())
        rel = path.relative_to(SRC).as_posix()
        for token in ("subprocess.Popen", "subprocess.call", "subprocess.check_output",
                      "os.system", "os.popen", "socket.", "shutil.rmtree", "urllib", "requests.",
                      "http.client", "winreg", "ctypes"):
            if token in code:
                offenders.append(f"{rel}:{token}")
        for token in ("eval", "exec", "compile"):
            if re.search(r"(?<![\w.])" + token + r"\(", code):
                offenders.append(f"{rel}:{token}()")
        # subprocess is permitted only to read the git SHA for run metadata
        if "import subprocess" in code and rel != "bench/run.py":
            offenders.append(f"{rel}:subprocess")
    assert offenders == [], offenders


def test_the_only_subprocess_call_is_reading_the_git_sha():
    import inspect

    from rv2.bench import run
    source = inspect.getsource(run.git_sha)
    assert "rev-parse" in source
    other = code_only(inspect.getsource(run)).count("subprocess")
    assert other <= 2  # the import and the single call inside git_sha


def test_no_module_writes_outside_the_experiment_directory():
    """Every path written is built from a caller-supplied root."""
    for path in SRC.rglob("*.py"):
        code = code_only(path.read_text())
        assert 'Path("/' not in code, path
        assert "C:\\\\Windows" not in code, path


def test_remediation_actions_are_data_not_commands():
    """The simulator applies structured mutations; nothing is ever a command string."""
    import inspect

    from rv2.world import scenarios
    source = code_only(inspect.getsource(scenarios))
    for token in ("powershell", "cmd.exe", "Invoke-", "Start-Process", "msiexec"):
        assert token.lower() not in source.lower()


def test_real_windows_adapter_is_absent_and_gated():
    """v2 ships no real-endpoint adapter at all; the flag remains a future-only gate."""
    assert not (SRC / "adapters").exists()
    root = SRC.parent.parent
    readme = (root / "README.md").read_text()
    assert "ALLOW_REAL_WINDOWS_LAB" in readme


def test_safety_flag_is_not_set_in_this_environment():
    assert os.environ.get("ALLOW_REAL_WINDOWS_LAB") != "1"


def test_a_full_run_touches_no_network(monkeypatch):
    """Poison the socket module, then run a slice of the benchmark."""
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("benchmark attempted a network connection")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    from rv2.bench.generate import generate
    from rv2.bench.run import run_predictions
    records, packages = run_predictions(generate("dev")[:40])
    assert records and packages


def test_a_full_run_starts_no_process(monkeypatch):
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError("benchmark attempted to start a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    from rv2.bench.generate import generate
    from rv2.bench.run import run_predictions
    records, _ = run_predictions(generate("holdout")[:40])
    assert records


def test_no_third_party_runtime_dependency():
    """Import the whole package with only the standard library available."""
    import importlib
    for module in ["rv2.world.scenarios", "rv2.oracle.truth", "rv2.collect.collector",
                   "rv2.obs.package", "rv2.verifiers", "rv2.bench.run",
                   "rv2.metrics.metrics", "rv2.analysis.reports"]:
        imported = importlib.import_module(module)
        for name in dir(imported):
            value = getattr(imported, name)
            module_name = getattr(value, "__module__", "") or ""
            assert not module_name.startswith(("numpy", "pandas", "scipy", "matplotlib")), name
