"""Real collection must be unreachable without every gate."""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from rv3.collectors.real import provision_fixtures, remove_fixtures, run_collector
from rv3.lab.gates import (
    ConfirmationMissing,
    GateNotSet,
    GateState,
    LabGateError,
    WrongPlatform,
    read_gates,
    require_fixture_setup,
    require_real_lab,
    require_windows,
)
from rv3.vocab import GATE_CONFIRMATION, GATE_FIXTURE_SETUP, GATE_REAL_LAB

TARGET = {"fixture_id": "fx-test", "file_root": "C:\\RV3Lab",
          "registry_root": "SOFTWARE\\RV3Lab", "arp_prefix": "RV3Lab_"}


def _state(**kwargs) -> GateState:
    base = {"fixture_setup": False, "real_lab": False, "confirmation": None,
            "platform_system": "Windows", "hostname": "LABVM"}
    base.update(kwargs)
    return GateState(**base)


# ------------------------------------------------------------------ platform
def test_non_windows_host_cannot_run_windows_collection():
    with pytest.raises(WrongPlatform):
        require_windows(_state(platform_system="Linux"))


def test_this_host_is_not_windows_so_everything_is_blocked():
    assert read_gates().platform_system != "Windows"
    with pytest.raises(LabGateError):
        run_collector("A_UNINSTALL_REGISTRY", Path("powershell"), TARGET)


# ------------------------------------------------------------------ gates
def test_real_lab_gate_is_required():
    with pytest.raises(GateNotSet):
        require_real_lab(_state(real_lab=False, confirmation="LABVM"))


def test_confirmation_is_required_even_with_the_flag_set():
    with pytest.raises(ConfirmationMissing):
        require_real_lab(_state(real_lab=True, confirmation=None))


def test_confirmation_must_name_this_machine():
    with pytest.raises(ConfirmationMissing):
        require_real_lab(_state(real_lab=True, confirmation="SOME-OTHER-HOST"))


def test_all_three_conditions_open_the_collection_gate():
    require_real_lab(_state(real_lab=True, confirmation="labvm"))


def test_fixture_setup_needs_its_own_gate_on_top():
    with pytest.raises(GateNotSet):
        require_fixture_setup(_state(real_lab=True, confirmation="LABVM", fixture_setup=False))
    require_fixture_setup(_state(real_lab=True, confirmation="LABVM", fixture_setup=True))


def test_setting_only_the_setup_gate_is_not_enough():
    with pytest.raises(GateNotSet):
        require_fixture_setup(_state(fixture_setup=True, confirmation="LABVM"))


@pytest.mark.parametrize("gate", [GATE_FIXTURE_SETUP, GATE_REAL_LAB, GATE_CONFIRMATION])
def test_gates_are_unset_in_this_environment(gate, monkeypatch):
    import os
    assert os.environ.get(gate) in (None, "")


# ------------------------------------------------------------------ writes
def test_every_writing_entry_point_checks_a_gate_first():
    for func, expected in ((run_collector, "require_real_lab"),
                           (provision_fixtures, "require_fixture_setup"),
                           (remove_fixtures, "require_fixture_setup")):
        source = inspect.getsource(func)
        body = source.split(":", 1)[1]
        assert expected in body, func.__name__
        gate_position = body.index(expected)
        for risky in ("subprocess", "_powershell"):
            if risky in body:
                assert body.index(risky) > gate_position, f"{func.__name__} touches {risky} first"


def test_provisioning_is_blocked_on_this_host():
    with pytest.raises(LabGateError):
        provision_fixtures(Path("powershell"), Path("plan.json"))
    with pytest.raises(LabGateError):
        remove_fixtures(Path("powershell"), Path("plan.json"))


def test_preflight_reports_blocked_and_never_raises():
    from rv3.lab.preflight import preflight
    result = preflight(40, ["A_UNINSTALL_REGISTRY"], with_setup=True)
    assert result["may_proceed"] is False
    assert result["blocked_reason"]
    assert "BLOCKED_NOT_EXECUTED" in result["rendered"]


def test_preflight_names_every_action_before_it_happens():
    from rv3.lab.preflight import preflight
    result = preflight(40, ["A_UNINSTALL_REGISTRY", "F_COMPOSITE_ACTIVE"], with_setup=True)
    joined = " ".join(result["actions"])
    assert "CREATE 40 lab fixtures" in joined
    assert "REMOVE every fixture" in joined
    assert "RUN read-only collector A_UNINSTALL_REGISTRY" in joined
    assert "WRITES to this machine" in joined


def test_preflight_requires_hostname_confirmation_even_on_windows(monkeypatch):
    from rv3.lab import preflight as module
    monkeypatch.setattr(module, "resolve_identity",
                        lambda: module.MachineIdentity(hostname="LABVM", platform_system="Windows",
                                                       platform_release="10", platform_version="x",
                                                       machine="AMD64"))
    result = module.preflight(40, ["A_UNINSTALL_REGISTRY"], True,
                              env={GATE_REAL_LAB: "1", GATE_FIXTURE_SETUP: "1"})
    assert result["may_proceed"] is False
    assert GATE_CONFIRMATION in result["blocked_reason"]

    result = module.preflight(40, ["A_UNINSTALL_REGISTRY"], True,
                              env={GATE_REAL_LAB: "1", GATE_FIXTURE_SETUP: "1",
                                   GATE_CONFIRMATION: "WRONG-HOST"})
    assert result["may_proceed"] is False

    result = module.preflight(40, ["A_UNINSTALL_REGISTRY"], True,
                              env={GATE_REAL_LAB: "1", GATE_FIXTURE_SETUP: "1",
                                   GATE_CONFIRMATION: "LABVM"})
    assert result["may_proceed"] is True
