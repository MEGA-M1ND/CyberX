"""Case model, split three ways to make ground-truth leakage structurally hard.

  PublicCase   -> everything a verifier arm is allowed to see
  Scenario     -> harness-only: initial state, what the remediation really did,
                  what the management tool reported, how blind the collector is
  GroundTruth  -> scorer-only label

The three live in separate files on disk and are loaded by separate functions.
`load_public_cases()` is the ONLY loader a verifier ever gets output from.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from .models import ExecutionResult, GroundTruth
from .simulator.state import EndpointState

# Standing library of "did the remediation leave the box in a newly unsafe
# configuration?" predicates.  It is identical for every case, so its presence
# tells a verifier nothing about which case it is looking at.
STANDING_RISK_PREDICATES: List[Dict[str, Any]] = [
    {"id": "SMB1_ENABLED", "op": "flag_true", "flag": "smb1_enabled"},
    {"id": "FIREWALL_DISABLED", "op": "flag_true", "flag": "host_firewall_disabled"},
    {"id": "RT_PROTECTION_DISABLED", "op": "flag_true", "flag": "realtime_protection_disabled"},
    {"id": "LEGACY_TLS_REENABLED", "op": "flag_true", "flag": "tls10_enabled"},
    {"id": "UNSIGNED_SCRIPTS_ALLOWED", "op": "flag_true", "flag": "unrestricted_script_policy"},
    {"id": "WORLD_WRITABLE_SHARE", "op": "flag_true", "flag": "world_writable_share"},
    {"id": "LOCAL_ADMIN_ADDED", "op": "flag_true", "flag": "unexpected_local_admin"},
    {"id": "CREDENTIAL_CACHE_ENABLED", "op": "flag_true", "flag": "cached_creds_unlimited"},
]


@dataclass
class PublicCase:
    case_id: str
    title: str
    os: str
    fleet_size: int
    vulnerability_predicate: Dict[str, Any]
    remediation_intent: Dict[str, Any]
    required_health_checks: List[str] = field(default_factory=list)
    notes: str = ""

    @property
    def target_state_assertions(self) -> List[Dict[str, Any]]:
        return list(self.remediation_intent.get("target_state_assertions", []))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "os": self.os,
            "fleet_size": self.fleet_size,
            "vulnerability_predicate": self.vulnerability_predicate,
            "remediation_intent": self.remediation_intent,
            "required_health_checks": self.required_health_checks,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PublicCase":
        return cls(
            case_id=d["case_id"],
            title=d["title"],
            os=d["os"],
            fleet_size=int(d["fleet_size"]),
            vulnerability_predicate=d["vulnerability_predicate"],
            remediation_intent=d["remediation_intent"],
            required_health_checks=list(d.get("required_health_checks", [])),
            notes=d.get("notes", ""),
        )


@dataclass
class Environment:
    """How lossy the evidence collector is on this endpoint.

    `unavailable_evidence` is *honest* blindness: the collector knows it failed
    and says so.  `blind_spots` is *silent* blindness: the collector returns a
    confident but incomplete inventory.  The distinction is the whole point of
    Category L versus the silent-blind-spot variants.
    """

    unavailable_evidence: List[str] = field(default_factory=list)
    blind_spot_package_versions: Dict[str, List[str]] = field(default_factory=dict)
    blind_spot_registry_paths: List[str] = field(default_factory=list)
    blind_spot_files: List[str] = field(default_factory=list)
    blind_spot_flags: List[str] = field(default_factory=list)
    collector_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unavailable_evidence": self.unavailable_evidence,
            "blind_spot_package_versions": self.blind_spot_package_versions,
            "blind_spot_registry_paths": self.blind_spot_registry_paths,
            "blind_spot_files": self.blind_spot_files,
            "blind_spot_flags": self.blind_spot_flags,
            "collector_note": self.collector_note,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Environment":
        return cls(
            unavailable_evidence=list(d.get("unavailable_evidence", [])),
            blind_spot_package_versions={k: list(v) for k, v in d.get("blind_spot_package_versions", {}).items()},
            blind_spot_registry_paths=list(d.get("blind_spot_registry_paths", [])),
            blind_spot_files=list(d.get("blind_spot_files", [])),
            blind_spot_flags=list(d.get("blind_spot_flags", [])),
            collector_note=d.get("collector_note", ""),
        )


@dataclass
class Scenario:
    """Harness-only simulation definition."""

    case_id: str
    initial_states: List[Dict[str, Any]]
    remediation_ops: List[List[Dict[str, Any]]]  # one op list per device
    execution_result: Dict[str, Any]
    reboot_effects: List[Dict[str, Any]] = field(default_factory=list)
    environment: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "initial_states": self.initial_states,
            "remediation_ops": self.remediation_ops,
            "execution_result": self.execution_result,
            "reboot_effects": self.reboot_effects,
            "environment": self.environment,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Scenario":
        return cls(
            case_id=d["case_id"],
            initial_states=d["initial_states"],
            remediation_ops=d["remediation_ops"],
            execution_result=d["execution_result"],
            reboot_effects=d.get("reboot_effects", []),
            environment=d.get("environment", {}),
        )

    def endpoint_states(self) -> List[EndpointState]:
        return [EndpointState.from_dict(s) for s in self.initial_states]

    def execution(self) -> ExecutionResult:
        return ExecutionResult(**self.execution_result)

    def env(self) -> Environment:
        return Environment.from_dict(self.environment)


# --------------------------------------------------------------------------- #
# Loaders.  Deliberately separate so that "who is allowed to read what" is a
# call-site-visible property.
# --------------------------------------------------------------------------- #
def load_public_cases(path: Path) -> List[PublicCase]:
    data = json.loads(Path(path).read_text())
    return [PublicCase.from_dict(d) for d in data["cases"]]


def load_scenarios(path: Path) -> Dict[str, Scenario]:
    data = json.loads(Path(path).read_text())
    return {d["case_id"]: Scenario.from_dict(d) for d in data["scenarios"]}


def load_ground_truth(path: Path) -> Dict[str, GroundTruth]:
    data = json.loads(Path(path).read_text())
    return {d["case_id"]: GroundTruth(**d) for d in data["ground_truth"]}
