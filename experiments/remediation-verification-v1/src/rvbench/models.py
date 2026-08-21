"""Core typed models for the remediation-verification benchmark.

Stdlib only. Everything here is deterministic and JSON-serialisable.
"""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

EXPERIMENT_VERSION = "remediation-verification-v1"


class Verdict(str, enum.Enum):
    """The closed vocabulary every verifier arm and the ground truth share."""

    VERIFIED_REMEDIATED = "VERIFIED_REMEDIATED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    PARTIALLY_REMEDIATED = "PARTIALLY_REMEDIATED"
    REGRESSION_INTRODUCED = "REGRESSION_INTRODUCED"
    NEW_SECURITY_RISK = "NEW_SECURITY_RISK"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


ALL_VERDICTS: List[str] = [v.value for v in Verdict]


class EvidenceType(str, enum.Enum):
    EXECUTION_STATUS = "EXECUTION_STATUS"
    PACKAGE_STATE = "PACKAGE_STATE"
    PATCH_STATE = "PATCH_STATE"
    REGISTRY_STATE = "REGISTRY_STATE"
    SERVICE_STATE = "SERVICE_STATE"
    FILE_STATE = "FILE_STATE"
    REBOOT_STATE = "REBOOT_STATE"
    SECURITY_PREDICATE = "SECURITY_PREDICATE"
    SMOKE_TEST = "SMOKE_TEST"
    FLEET_COVERAGE = "FLEET_COVERAGE"


ALL_EVIDENCE_TYPES: List[str] = [e.value for e in EvidenceType]


class Category(str, enum.Enum):
    """Benchmark failure-mode taxonomy (see methodology.md)."""

    A_GENUINE_SUCCESS = "A_GENUINE_SUCCESS"
    B_EXIT0_NO_CHANGE = "B_EXIT0_NO_CHANGE"
    C_WRONG_TARGET = "C_WRONG_TARGET"
    D_TEMPORARY = "D_TEMPORARY"
    E_SIDE_BY_SIDE = "E_SIDE_BY_SIDE"
    F_PARTIAL = "F_PARTIAL"
    G_FLEET_PARTIAL = "G_FLEET_PARTIAL"
    H_REGRESSION = "H_REGRESSION"
    I_NEW_RISK = "I_NEW_RISK"
    J_REBOOT_REQUIRED = "J_REBOOT_REQUIRED"
    K_WRONG_VULN_MATCH = "K_WRONG_VULN_MATCH"
    L_EVIDENCE_MISSING = "L_EVIDENCE_MISSING"


class Tri(str, enum.Enum):
    """Three-valued logic. UNKNOWN is what makes fail-closed semantics possible."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ExecutionResult:
    """What a device-management tool reports back after running a remediation."""

    exit_code: int = 0
    execution_status: str = "Succeeded"
    deployment_status: str = "Succeeded"
    stdout: str = ""
    stderr: str = ""
    devices_targeted: int = 1
    devices_reported_success: int = 1
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Observation:
    """A single collected evidence item. `available=False` means 'could not collect'."""

    evidence_type: str
    available: bool
    value: Any = None
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerifierOutput:
    verdict: str
    confidence: float
    reason_codes: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    arm: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GroundTruth:
    """Hidden. Only the scorer may read this."""

    case_id: str
    label: str
    category: str
    rationale: str
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
