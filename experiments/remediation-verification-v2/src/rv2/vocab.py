"""Shared closed vocabularies.

Deliberately data-only: enums and label sets, no decision logic.  Both the
oracle and the verifiers name their outputs from here, but neither borrows the
other's reasoning - that separation is the point of v2 and is checked by
tests/test_layering.py.
"""
from __future__ import annotations

import enum
from typing import List


class Verdict(str, enum.Enum):
    """What a verifier may output."""

    VERIFIED_REMEDIATED = "VERIFIED_REMEDIATED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    PARTIALLY_REMEDIATED = "PARTIALLY_REMEDIATED"
    REGRESSION_INTRODUCED = "REGRESSION_INTRODUCED"
    NEW_SECURITY_RISK = "NEW_SECURITY_RISK"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class TruthLabel(str, enum.Enum):
    """What the oracle may output.

    Note the asymmetry with Verdict: the oracle reads the latent world, which is
    always fully determined, so it can never be short of evidence.  There is no
    INSUFFICIENT_EVIDENCE truth label in v2.  (v1 had one; that conflated a
    property of the collector with a property of the endpoint.)
    """

    VERIFIED_REMEDIATED = "VERIFIED_REMEDIATED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    PARTIALLY_REMEDIATED = "PARTIALLY_REMEDIATED"
    REGRESSION_INTRODUCED = "REGRESSION_INTRODUCED"
    NEW_SECURITY_RISK = "NEW_SECURITY_RISK"


ALL_VERDICTS: List[str] = [v.value for v in Verdict]
ALL_TRUTH_LABELS: List[str] = [t.value for t in TruthLabel]

# Metric denominators, stated once so every report uses the same sets.
#
# UNSAFE      the vulnerable condition, or a newly created exposure, is still
#             present on at least one in-scope device
# HARM        the remediation caused damage: broke a required application, or
#             created a new exposure
# REMEDIATED  clean, persistent, complete, and harmless
UNSAFE_LABELS = frozenset({
    TruthLabel.REMEDIATION_FAILED.value,
    TruthLabel.PARTIALLY_REMEDIATED.value,
    TruthLabel.NEW_SECURITY_RISK.value,
})
HARM_LABELS = frozenset({
    TruthLabel.REGRESSION_INTRODUCED.value,
    TruthLabel.NEW_SECURITY_RISK.value,
})
REMEDIATED_LABELS = frozenset({TruthLabel.VERIFIED_REMEDIATED.value})


class EvidenceType(str, enum.Enum):
    EXECUTION_REPORT = "EXECUTION_REPORT"
    PACKAGE_INVENTORY = "PACKAGE_INVENTORY"
    FILE_STATE = "FILE_STATE"
    REGISTRY_STATE = "REGISTRY_STATE"
    SERVICE_STATE = "SERVICE_STATE"
    PATCH_STATE = "PATCH_STATE"
    REBOOT_STATE = "REBOOT_STATE"
    SECURITY_POSTURE = "SECURITY_POSTURE"
    APPLICATION_HEALTH = "APPLICATION_HEALTH"
    GROUP_MEMBERSHIP = "GROUP_MEMBERSHIP"


ALL_EVIDENCE_TYPES: List[str] = [e.value for e in EvidenceType]

# Evidence classes that speak to whether the endpoint is still vulnerable.
VULNERABILITY_EVIDENCE = frozenset({
    EvidenceType.PACKAGE_INVENTORY.value,
    EvidenceType.FILE_STATE.value,
    EvidenceType.REGISTRY_STATE.value,
    EvidenceType.SERVICE_STATE.value,
    EvidenceType.PATCH_STATE.value,
})


class Mechanism(str, enum.Enum):
    """How evidence is degraded to reach a target coverage level."""

    NONE = "NONE"
    RANDOM_MISSING = "RANDOM_MISSING"
    DECISIVE_FIELD_MISSING = "DECISIVE_FIELD_MISSING"
    REGRESSION_EVIDENCE_MISSING = "REGRESSION_EVIDENCE_MISSING"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"


ADVERSARIAL_MECHANISMS = frozenset({
    Mechanism.DECISIVE_FIELD_MISSING.value,
    Mechanism.REGRESSION_EVIDENCE_MISSING.value,
    Mechanism.SCOPE_MISMATCH.value,
    Mechanism.CONTRADICTORY_EVIDENCE.value,
    Mechanism.STALE_EVIDENCE.value,
})
RANDOM_MECHANISMS = frozenset({Mechanism.RANDOM_MISSING.value})


class FailureReason(str, enum.Enum):
    """Why a requested collection did not fully succeed."""

    PERMISSION_DENIED = "PERMISSION_DENIED"
    TIMEOUT = "TIMEOUT"
    UNSUPPORTED = "UNSUPPORTED"
    SCOPE_NARROWED = "SCOPE_NARROWED"
    STALE = "STALE"
    CONTRADICTED = "CONTRADICTED"
    DEVICE_NOT_ENUMERATED = "DEVICE_NOT_ENUMERATED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"


ARMS: List[str] = [
    "A_STATUS_ONLY",
    "B_TARGET_STATE",
    "C_SCOPE_UNAWARE_INDEPENDENT",
    "D_SCOPE_AWARE_FAIL_CLOSED",
    "E_ACTIVE_EVIDENCE",
]
