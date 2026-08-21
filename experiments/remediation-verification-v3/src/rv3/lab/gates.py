"""Safety gates.

Three independent conditions must all hold before anything touches a real
machine, and each failure is a distinct exception so a test can prove which one
did the blocking:

    ALLOW_WINDOWS_FIXTURE_SETUP=1   permits creating fixtures on the lab VM
    ALLOW_REAL_WINDOWS_LAB=1        permits running collectors on a real machine
    RV3_LAB_CONFIRMATION=<hostname> the operator typing the target's own name

The third is deliberately not a boolean.  A flag can be set by a stray
environment file; naming the machine you are about to modify cannot be done by
accident.
"""
from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..vocab import GATE_CONFIRMATION, GATE_FIXTURE_SETUP, GATE_REAL_LAB


class LabGateError(RuntimeError):
    """Base class: real execution was refused."""


class GateNotSet(LabGateError):
    pass


class ConfirmationMissing(LabGateError):
    pass


class WrongPlatform(LabGateError):
    pass


@dataclass(frozen=True)
class GateState:
    fixture_setup: bool
    real_lab: bool
    confirmation: Optional[str]
    platform_system: str
    hostname: str

    @property
    def all_open(self) -> bool:
        return bool(self.fixture_setup and self.real_lab and self.confirmation)

    def to_dict(self) -> Dict[str, Any]:
        return {
            GATE_FIXTURE_SETUP: "1" if self.fixture_setup else "<unset>",
            GATE_REAL_LAB: "1" if self.real_lab else "<unset>",
            GATE_CONFIRMATION: self.confirmation or "<unset>",
            "platform": self.platform_system,
            "hostname": self.hostname,
        }


def read_gates(env: Optional[Dict[str, str]] = None) -> GateState:
    source = dict(os.environ if env is None else env)
    try:
        hostname = socket.gethostname()
    except Exception:  # pragma: no cover - hostname lookup should not break a run
        hostname = "unknown"
    return GateState(
        fixture_setup=source.get(GATE_FIXTURE_SETUP) == "1",
        real_lab=source.get(GATE_REAL_LAB) == "1",
        confirmation=source.get(GATE_CONFIRMATION) or None,
        platform_system=platform.system(),
        hostname=hostname,
    )


def require_windows(state: Optional[GateState] = None) -> None:
    state = state or read_gates()
    if state.platform_system != "Windows":
        raise WrongPlatform(
            f"Windows collection cannot run on {state.platform_system!r}. "
            "This experiment executes real collectors only on a disposable Windows lab VM."
        )


def require_real_lab(state: Optional[GateState] = None) -> None:
    """Gate for running read-only collectors against a real machine."""
    state = state or read_gates()
    require_windows(state)
    if not state.real_lab:
        raise GateNotSet(f"{GATE_REAL_LAB}=1 is required before any real collection.")
    if not state.confirmation:
        raise ConfirmationMissing(
            f"{GATE_CONFIRMATION} must be set to the target machine's hostname. "
            "Naming the machine is the confirmation that it is the disposable lab VM."
        )
    if state.confirmation.strip().lower() != state.hostname.strip().lower():
        raise ConfirmationMissing(
            f"{GATE_CONFIRMATION}={state.confirmation!r} does not match this machine "
            f"({state.hostname!r}). Refusing: the confirmed target is not this host."
        )


def require_fixture_setup(state: Optional[GateState] = None) -> None:
    """Gate for the only path that writes anything - fixture provisioning."""
    state = state or read_gates()
    require_real_lab(state)
    if not state.fixture_setup:
        raise GateNotSet(
            f"{GATE_FIXTURE_SETUP}=1 is required before creating or removing lab fixtures. "
            "Fixture provisioning writes to the machine and must never run outside the lab VM."
        )
