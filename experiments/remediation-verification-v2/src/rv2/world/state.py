"""Latent endpoint state and the fleet timeline.

Two things distinguish this from the v1 state model, and both exist to support
evidence conditions v1 could not express:

  * Package inventory and on-disk file state are independent.  A vendor
    installer can bump the ARP entry without replacing the executable, which is
    a real and nasty way for a fix to look applied while the vulnerable code
    keeps running.
  * State is a timeline, not a snapshot.  Every device carries its baseline,
    post-remediation, and (if a reboot happened) post-reboot state, each stamped
    with a time.  Staleness is then a real property - evidence sampled from an
    earlier snapshot - rather than a flag someone sets.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Simulated wall clock.  Fixed integers, not a real clock: reproducibility
# depends on nothing here moving between runs.
T_BASELINE = 1_000
T_REMEDIATION = 2_000
T_REBOOT = 3_000
T_COLLECTION = 4_000

INSTALL_SCOPES = ("machine", "per_user")
REGISTRY_ROOTS = ("HKLM\\SOFTWARE", "HKLM\\SOFTWARE\\WOW6432Node", "HKLM\\SYSTEM", "HKCU\\SOFTWARE")
FILESYSTEM_ROOTS = ("C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData", "C:\\Users")


def registry_root_of(path: str) -> str:
    """Longest declared root that prefixes this key."""
    best = ""
    for root in REGISTRY_ROOTS:
        if path.startswith(root) and len(root) > len(best):
            best = root
    return best or path.split("\\", 1)[0]


def filesystem_root_of(path: str) -> str:
    best = ""
    for root in FILESYSTEM_ROOTS:
        if path.startswith(root) and len(root) > len(best):
            best = root
    return best or path[:3]


@dataclass
class InstalledPackage:
    name: str
    version: str
    install_scope: str = "machine"  # machine | per_user
    product_code: str = ""

    def key(self) -> str:
        return f"{self.name}|{self.version}|{self.install_scope}"

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.version,
                "install_scope": self.install_scope, "product_code": self.product_code}


@dataclass
class DeviceState:
    """One point-in-time snapshot of a device."""

    packages: List[InstalledPackage] = field(default_factory=list)
    registry: Dict[str, Any] = field(default_factory=dict)
    services: Dict[str, Dict[str, str]] = field(default_factory=dict)
    files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    patches: Dict[str, Dict[str, bool]] = field(default_factory=dict)
    reboot_pending: bool = False
    application_health: Dict[str, bool] = field(default_factory=dict)
    security_posture: Dict[str, Any] = field(default_factory=dict)

    def clone(self) -> "DeviceState":
        return copy.deepcopy(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packages": sorted((p.to_dict() for p in self.packages), key=lambda d: (d["name"], d["version"], d["install_scope"])),
            "registry": dict(sorted(self.registry.items())),
            "services": {k: dict(v) for k, v in sorted(self.services.items())},
            "files": {k: dict(v) for k, v in sorted(self.files.items())},
            "patches": {k: dict(v) for k, v in sorted(self.patches.items())},
            "reboot_pending": self.reboot_pending,
            "application_health": dict(sorted(self.application_health.items())),
            "security_posture": dict(sorted(self.security_posture.items())),
        }

    def fingerprint(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass
class Snapshot:
    at: int
    label: str  # baseline | post_remediation | post_reboot
    state: DeviceState


@dataclass
class LatentDevice:
    device_id: str
    os: str = "windows"
    timeline: List[Snapshot] = field(default_factory=list)
    # Some scenarios never reach the collector at all (offline, not enumerated).
    enumerable: bool = True

    @property
    def current(self) -> DeviceState:
        return self.timeline[-1].state

    @property
    def current_at(self) -> int:
        return self.timeline[-1].at

    def snapshot(self, label: str) -> Optional[Snapshot]:
        for snap in self.timeline:
            if snap.label == label:
                return snap
        return None

    def snapshot_or_current(self, label: str) -> Snapshot:
        return self.snapshot(label) or self.timeline[-1]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "os": self.os,
            "enumerable": self.enumerable,
            "timeline": [{"at": s.at, "label": s.label, "state": s.state.to_dict()} for s in self.timeline],
        }


@dataclass
class ExecutionReport:
    """What the delivery tool claims happened.  Deliberately allowed to lie."""

    exit_code: int = 0
    execution_status: str = "Succeeded"
    deployment_status: str = "Succeeded"
    devices_targeted: int = 1
    devices_reported_success: int = 1
    completed_at: int = T_REMEDIATION
    stdout: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "execution_status": self.execution_status,
            "deployment_status": self.deployment_status,
            "devices_targeted": self.devices_targeted,
            "devices_reported_success": self.devices_reported_success,
            "completed_at": self.completed_at,
            "stdout": self.stdout,
        }


@dataclass
class LatentWorld:
    """The whole truth about one remediation attempt against one device group."""

    case_id: str
    family: str
    devices: List[LatentDevice]
    targeted_device_ids: List[str]
    execution: ExecutionReport
    reboot_performed: bool
    vulnerability_predicate: Dict[str, Any]
    remediation_intent: Dict[str, Any]
    required_health_checks: List[str]
    decisive_hint: Dict[str, Any] = field(default_factory=dict)
    collected_at: int = T_COLLECTION

    def device(self, device_id: str) -> LatentDevice:
        for d in self.devices:
            if d.device_id == device_id:
                return d
        raise KeyError(device_id)

    @property
    def enumerable_devices(self) -> List[LatentDevice]:
        return [d for d in self.devices if d.enumerable]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "family": self.family,
            "devices": [d.to_dict() for d in self.devices],
            "targeted_device_ids": list(self.targeted_device_ids),
            "execution": self.execution.to_dict(),
            "reboot_performed": self.reboot_performed,
            "vulnerability_predicate": self.vulnerability_predicate,
            "remediation_intent": self.remediation_intent,
            "required_health_checks": list(self.required_health_checks),
        }


# --------------------------------------------------------------------------- #
# Version comparison.  Deliberately local to the world package; the observation
# side has its own copy, so the two layers cannot drift into a shared helper.
# --------------------------------------------------------------------------- #
def parse_version(value: str) -> List[int]:
    out: List[int] = []
    for part in str(value).split("."):
        digits = ""
        for ch in part:
            if not ch.isdigit():
                break
            digits += ch
        out.append(int(digits) if digits else -1)
    return out


def version_below(candidate: str, fixed: str) -> bool:
    a, b = parse_version(candidate), parse_version(fixed)
    n = max(len(a), len(b))
    return (a + [0] * (n - len(a))) < (b + [0] * (n - len(b)))


def project_reboot(state: DeviceState) -> DeviceState:
    """What this device looks like after its next restart.

    Mechanical and non-destructive: automatic services come back, disabled ones
    stay down, staged patches land, pending-reboot clears.
    """
    s = state.clone()
    for svc in s.services.values():
        if svc.get("startup_type") == "automatic":
            svc["status"] = "running"
        elif svc.get("startup_type") == "disabled":
            svc["status"] = "stopped"
    for patch in s.patches.values():
        if patch.get("staged"):
            patch["installed"] = True
            patch["staged"] = False
    s.reboot_pending = False
    return s
