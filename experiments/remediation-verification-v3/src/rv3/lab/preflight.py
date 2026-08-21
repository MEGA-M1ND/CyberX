"""Preflight: say exactly what is about to happen, to which machine, and stop.

Printed before any real execution.  It resolves the machine identity, the OS
build, whether the host looks like a virtual machine, both gate values, and the
full list of actions - and it refuses if anything is missing.
"""
from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..vocab import GATE_CONFIRMATION, GATE_FIXTURE_SETUP, GATE_REAL_LAB
from .gates import GateState, read_gates

VM_HINTS = ("virtual", "vmware", "kvm", "qemu", "hyper-v", "hyperv", "xen", "virtualbox",
            "parallels", "bochs")


@dataclass
class MachineIdentity:
    hostname: str
    platform_system: str
    platform_release: str
    platform_version: str
    machine: str
    manufacturer: str = "unknown"
    model: str = "unknown"
    os_caption: str = "unknown"
    domain_joined: Optional[bool] = None
    looks_like_vm: Optional[bool] = None
    detection_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


def _windows_identity() -> Dict[str, str]:  # pragma: no cover - Windows only
    """Read-only CIM queries.  Never Win32_Product."""
    script = (
        "$cs = Get-CimInstance Win32_ComputerSystem;"
        "$os = Get-CimInstance Win32_OperatingSystem;"
        "[pscustomobject]@{manufacturer=$cs.Manufacturer; model=$cs.Model;"
        " domain=$cs.PartOfDomain; caption=$os.Caption; version=$os.Version} | ConvertTo-Json"
    )
    proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        return {}
    return json.loads(proc.stdout or "{}")


def resolve_identity() -> MachineIdentity:
    identity = MachineIdentity(
        hostname=platform.node(),
        platform_system=platform.system(),
        platform_release=platform.release(),
        platform_version=platform.version(),
        machine=platform.machine(),
    )
    if identity.platform_system != "Windows":
        identity.detection_note = ("not Windows; VM detection and CIM identity are unavailable "
                                   "on this platform")
        return identity
    try:  # pragma: no cover - Windows only
        data = _windows_identity()
        identity.manufacturer = str(data.get("manufacturer", "unknown"))
        identity.model = str(data.get("model", "unknown"))
        identity.os_caption = str(data.get("caption", "unknown"))
        identity.domain_joined = bool(data.get("domain")) if "domain" in data else None
        blob = f"{identity.manufacturer} {identity.model}".lower()
        identity.looks_like_vm = any(hint in blob for hint in VM_HINTS)
        identity.detection_note = "identity read via read-only CIM queries"
    except Exception as exc:  # pragma: no cover - Windows only
        identity.detection_note = f"identity detection failed: {exc}"
    return identity


def planned_actions(fixture_count: int, collector_ids: List[str], with_setup: bool) -> List[str]:
    actions: List[str] = []
    if with_setup:
        actions.append(f"CREATE {fixture_count} lab fixtures under C:\\RV3Lab, "
                       "HKLM/HKCU\\SOFTWARE\\RV3Lab, ARP keys prefixed RV3Lab_, "
                       "services and scheduled tasks prefixed RV3Lab_, and disposable "
                       "local accounts prefixed rv3lab_ (WRITES to this machine)")
    for collector_id in collector_ids:
        actions.append(f"RUN read-only collector {collector_id}")
    if with_setup:
        actions.append("REMOVE every fixture created above (WRITES to this machine)")
    actions.append("WRITE collector output to the experiment's artifacts directory")
    return actions


def render(identity: MachineIdentity, gates: GateState, actions: List[str],
           blocked_reason: Optional[str]) -> str:
    lines = [
        "=" * 72,
        "  REMEDIATION VERIFICATION v3 - PREFLIGHT",
        "=" * 72,
        "",
        "  TARGET MACHINE",
        f"    hostname          {identity.hostname}",
        f"    platform          {identity.platform_system} {identity.platform_release}",
        f"    os                {identity.os_caption}",
        f"    manufacturer      {identity.manufacturer}",
        f"    model             {identity.model}",
        f"    domain joined     {identity.domain_joined}",
        f"    looks like a VM   {identity.looks_like_vm}",
        f"    note              {identity.detection_note}",
        "",
        "  GATES",
        f"    {GATE_FIXTURE_SETUP:<30} {'1' if gates.fixture_setup else '<unset>'}",
        f"    {GATE_REAL_LAB:<30} {'1' if gates.real_lab else '<unset>'}",
        f"    {GATE_CONFIRMATION:<30} {gates.confirmation or '<unset>'}",
        "",
        "  ACTIONS THAT WOULD BE PERFORMED",
    ]
    lines += [f"    {i + 1:>2}. {action}" for i, action in enumerate(actions)]
    lines += ["", "  CONFIRMATION REQUIRED",
              f"    Set {GATE_CONFIRMATION} to this machine's own hostname "
              f"({identity.hostname!r}) to confirm it is the disposable lab VM.",
              "    Never run this against a host machine, a corporate endpoint, a production",
              "    tenant, or any machine you are not prepared to discard.", ""]
    if blocked_reason:
        lines += ["  RESULT", f"    BLOCKED_NOT_EXECUTED - {blocked_reason}", ""]
    else:  # pragma: no cover - only reachable on a confirmed lab VM
        lines += ["  RESULT", "    All gates open. Proceeding with the actions listed above.", ""]
    lines.append("=" * 72)
    return "\n".join(lines)


def preflight(fixture_count: int, collector_ids: List[str], with_setup: bool,
              env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Never raises.  Returns the full picture plus whether execution may proceed."""
    identity = resolve_identity()
    gates = read_gates(env)
    actions = planned_actions(fixture_count, collector_ids, with_setup)

    reason = None
    if identity.platform_system != "Windows":
        reason = (f"this is {identity.platform_system}, not Windows; no disposable Windows "
                  "lab VM is reachable from this session")
    elif not gates.real_lab:
        reason = f"{GATE_REAL_LAB} is not set to 1"
    elif with_setup and not gates.fixture_setup:
        reason = f"{GATE_FIXTURE_SETUP} is not set to 1"
    elif not gates.confirmation:
        reason = f"{GATE_CONFIRMATION} is not set"
    elif gates.confirmation.strip().lower() != identity.hostname.strip().lower():
        reason = (f"{GATE_CONFIRMATION}={gates.confirmation!r} does not name this machine "
                  f"({identity.hostname!r})")

    return {
        "identity": identity.to_dict(),
        "gates": gates.to_dict(),
        "actions": actions,
        "may_proceed": reason is None,
        "blocked_reason": reason,
        "rendered": render(identity, gates, actions, reason),
    }


def write_preflight(path: Path, result: Dict[str, Any]) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(result["rendered"] + "\n")
    return Path(path)
