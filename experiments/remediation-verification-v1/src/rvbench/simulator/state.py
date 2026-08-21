"""Deterministic endpoint state model.

The same class is used for the *true* simulator state and for the *observed*
state that a verifier gets to see.  The only difference is the `available`
set: an observed state may be missing whole evidence classes, which the
predicate evaluator turns into `Tri.UNKNOWN` rather than a silent `False`.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..models import EvidenceType

ALL_AVAILABLE: Set[str] = {e.value for e in EvidenceType}


@dataclass
class EndpointState:
    device_id: str = "device-001"
    os: str = "windows"
    # package name -> list of installed versions (a list, so side-by-side
    # installs of a vulnerable and a fixed build are representable)
    packages: Dict[str, List[str]] = field(default_factory=dict)
    registry: Dict[str, Any] = field(default_factory=dict)
    # service name -> {"status": running|stopped, "startup_type": automatic|manual|disabled}
    services: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # path -> {"exists": bool, "version": str|None}
    files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # kb id -> {"installed": bool, "staged": bool}
    patches: Dict[str, Dict[str, bool]] = field(default_factory=dict)
    reboot_pending: bool = False
    health_checks: Dict[str, bool] = field(default_factory=dict)
    security_flags: Dict[str, Any] = field(default_factory=dict)
    # Which evidence classes this view can speak about at all.
    available: Set[str] = field(default_factory=lambda: set(ALL_AVAILABLE))

    # ------------------------------------------------------------------ #
    def clone(self) -> "EndpointState":
        return copy.deepcopy(self)

    def has(self, evidence_type: EvidenceType) -> bool:
        return evidence_type.value in self.available

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "os": self.os,
            "packages": {k: list(v) for k, v in sorted(self.packages.items())},
            "registry": dict(sorted(self.registry.items())),
            "services": {k: dict(v) for k, v in sorted(self.services.items())},
            "files": {k: dict(v) for k, v in sorted(self.files.items())},
            "patches": {k: dict(v) for k, v in sorted(self.patches.items())},
            "reboot_pending": self.reboot_pending,
            "health_checks": dict(sorted(self.health_checks.items())),
            "security_flags": dict(sorted(self.security_flags.items())),
            "available": sorted(self.available),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EndpointState":
        return cls(
            device_id=d.get("device_id", "device-001"),
            os=d.get("os", "windows"),
            packages={k: list(v) for k, v in d.get("packages", {}).items()},
            registry=dict(d.get("registry", {})),
            services={k: dict(v) for k, v in d.get("services", {}).items()},
            files={k: dict(v) for k, v in d.get("files", {}).items()},
            patches={k: dict(v) for k, v in d.get("patches", {}).items()},
            reboot_pending=bool(d.get("reboot_pending", False)),
            health_checks=dict(d.get("health_checks", {})),
            security_flags=dict(d.get("security_flags", {})),
            available=set(d.get("available", ALL_AVAILABLE)),
        )

    def fingerprint(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def parse_version(v: str) -> List[int]:
    """Dotted-numeric version parse.  Non-numeric components sort as -1."""
    out: List[int] = []
    for part in str(v).split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        out.append(int(digits) if digits else -1)
    return out


def version_lt(a: str, b: str) -> bool:
    pa, pb = parse_version(a), parse_version(b)
    n = max(len(pa), len(pb))
    pa = pa + [0] * (n - len(pa))
    pb = pb + [0] * (n - len(pb))
    return pa < pb


def project_post_reboot(state: EndpointState, extra_effects: Optional[List[Dict[str, Any]]] = None) -> EndpointState:
    """Non-destructive projection of what the endpoint looks like after a reboot.

    Rules are mechanical and deterministic:
      * services with startup_type=automatic come back running
      * services with startup_type=disabled stay stopped
      * staged patches become installed
      * reboot_pending clears
      * any case-specific `reboot_effects` ops are applied last
    """
    from .engine import apply_ops  # local import to avoid a cycle

    s = state.clone()
    for svc in s.services.values():
        st = svc.get("startup_type")
        if st == "automatic":
            svc["status"] = "running"
        elif st == "disabled":
            svc["status"] = "stopped"
    for p in s.patches.values():
        if p.get("staged"):
            p["installed"] = True
            p["staged"] = False
    s.reboot_pending = False
    if extra_effects:
        apply_ops(s, extra_effects)
    return s
