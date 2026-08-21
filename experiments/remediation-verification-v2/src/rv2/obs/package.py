"""The observation package - the only thing a verifier ever sees.

Two views of the same collection exist, and which view an arm receives is what
makes the arm comparison structural rather than a matter of self-discipline:

  full view  (Arms D, E)  raw per-collector evidence items plus the collection
                          manifest: what was requested, what came back, what
                          failed, what scope was actually queried, when the
                          remediation and any reboot happened, which fields two
                          collectors disagree about.

  flat view  (Arms A, B, C)  one merged item per (evidence type, device), latest
                          collector wins, and NO manifest.  This models a
                          verifier reading a normalised inventory table rather
                          than the collector transcripts - which is what
                          scope-unaware tooling actually consumes.  A field that
                          was never collected is indistinguishable from a field
                          that does not exist.

Timestamps live on the items, so the flat view has them.  The *reference points*
they would have to be compared against - when the remediation finished, when the
device rebooted - live only in the manifest.  A clock with no zero is not a
freshness check.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Set

from ..vocab import EvidenceType

# Scope partitions a collector may or may not have queried, per evidence type.
FULL_SCOPE: Dict[str, List[str]] = {
    EvidenceType.PACKAGE_INVENTORY.value: ["machine", "per_user"],
    EvidenceType.REGISTRY_STATE.value: ["HKLM\\SOFTWARE", "HKLM\\SOFTWARE\\WOW6432Node",
                                        "HKLM\\SYSTEM", "HKCU\\SOFTWARE"],
    EvidenceType.SERVICE_STATE.value: ["automatic", "manual", "disabled"],
    EvidenceType.FILE_STATE.value: ["C:\\Program Files", "C:\\Program Files (x86)",
                                    "C:\\ProgramData", "C:\\Users"],
    EvidenceType.PATCH_STATE.value: ["security_update", "servicing_stack"],
    EvidenceType.APPLICATION_HEALTH.value: ["health"],
    EvidenceType.SECURITY_POSTURE.value: ["posture"],
    EvidenceType.REBOOT_STATE.value: ["reboot"],
    EvidenceType.GROUP_MEMBERSHIP.value: ["group"],
    EvidenceType.EXECUTION_REPORT.value: ["execution"],
}

FLEET_DEVICE = "*"  # device_id used for fleet-wide evidence


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    evidence_type: str
    device_id: str
    collector_id: str
    collector_version: str
    collected_at: int
    value: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "device_id": self.device_id,
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "collected_at": self.collected_at,
            "value": self.value,
        }


@dataclass(frozen=True)
class CollectionRequest:
    evidence_type: str
    device_id: str
    requested_scope_keys: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {"evidence_type": self.evidence_type, "device_id": self.device_id,
                "requested_scope_keys": list(self.requested_scope_keys)}


@dataclass(frozen=True)
class CollectionFailure:
    evidence_type: str
    device_id: str
    reason: str
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"evidence_type": self.evidence_type, "device_id": self.device_id,
                "reason": self.reason, "detail": self.detail}


@dataclass(frozen=True)
class Contradiction:
    evidence_type: str
    device_id: str
    field_key: str
    collectors: List[str]
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"evidence_type": self.evidence_type, "device_id": self.device_id,
                "field_key": self.field_key, "collectors": list(self.collectors),
                "detail": self.detail}


@dataclass(frozen=True)
class CollectionManifest:
    """Everything the collector knows about its own collection."""

    collector_identities: List[Dict[str, str]]
    requested: List[CollectionRequest]
    collected_evidence_ids: List[str]
    failed: List[CollectionFailure]
    unsupported: List[CollectionFailure]
    # evidence_id -> the scope partitions that query actually covered
    covered_scope_keys: Dict[str, List[str]]
    devices_requested: List[str]
    devices_observed: List[str]
    declared_group_scope: Dict[str, int]
    remediation_completed_at: int
    reboot_performed_at: Optional[int]
    reboot_pending_reported: Optional[bool]
    collection_started_at: int
    collection_completed_at: int
    freshness_seconds: Dict[str, int]
    contradictions: List[Contradiction]
    identity_mismatches: List[CollectionFailure] = field(default_factory=list)
    # The collector's own view of how much of its requested surface it believes
    # it covered.  Computed from this manifest alone, so a collector that is
    # wrong about its scope reports a confident, wrong number - which is the
    # whole point of the UNDECLARED_GAP condition.
    declared_coverage: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector_identities": self.collector_identities,
            "requested": [r.to_dict() for r in self.requested],
            "collected_evidence_ids": list(self.collected_evidence_ids),
            "failed": [f.to_dict() for f in self.failed],
            "unsupported": [f.to_dict() for f in self.unsupported],
            "covered_scope_keys": {k: list(v) for k, v in sorted(self.covered_scope_keys.items())},
            "devices_requested": list(self.devices_requested),
            "devices_observed": list(self.devices_observed),
            "declared_group_scope": dict(self.declared_group_scope),
            "remediation_completed_at": self.remediation_completed_at,
            "reboot_performed_at": self.reboot_performed_at,
            "reboot_pending_reported": self.reboot_pending_reported,
            "collection_started_at": self.collection_started_at,
            "collection_completed_at": self.collection_completed_at,
            "freshness_seconds": dict(sorted(self.freshness_seconds.items())),
            "contradictions": [c.to_dict() for c in self.contradictions],
            "identity_mismatches": [m.to_dict() for m in self.identity_mismatches],
            "declared_coverage": self.declared_coverage,
        }


@dataclass(frozen=True)
class ObservationPackage:
    package_id: str
    case_id: str
    collected_at: int
    execution_report: Dict[str, Any]
    remediation_intent: Dict[str, Any]
    vulnerability_predicate: Dict[str, Any]
    required_health_checks: List[str]
    standing_risk_predicates: List[Dict[str, Any]]
    items: List[EvidenceItem]
    manifest: Optional[CollectionManifest] = None

    # ------------------------------------------------------------------ #
    @property
    def target_state_assertions(self) -> List[Dict[str, Any]]:
        return list(self.remediation_intent.get("target_state_assertions", []))

    def device_ids(self) -> List[str]:
        return sorted({i.device_id for i in self.items if i.device_id != FLEET_DEVICE})

    def items_for(self, evidence_type: str, device_id: str) -> List[EvidenceItem]:
        return [i for i in self.items
                if i.evidence_type == evidence_type and i.device_id == device_id]

    def latest_item(self, evidence_type: str, device_id: str) -> Optional[EvidenceItem]:
        matches = self.items_for(evidence_type, device_id)
        if not matches:
            return None
        return sorted(matches, key=lambda i: (i.collected_at, i.evidence_id))[-1]

    def covered_scopes(self, item: EvidenceItem) -> Optional[Set[str]]:
        """Scope partitions this item's query actually covered.

        Returns None without a manifest: a flat-view consumer has no way to know,
        which is exactly the blindness being measured.
        """
        if self.manifest is None:
            return None
        return set(self.manifest.covered_scope_keys.get(item.evidence_id, []))

    # ------------------------------------------------------------------ #
    def flat_view(self) -> "ObservationPackage":
        """One merged item per (evidence type, device), no manifest."""
        merged: Dict[Any, EvidenceItem] = {}
        for item in sorted(self.items, key=lambda i: (i.collected_at, i.evidence_id)):
            merged[(item.evidence_type, item.device_id)] = item
        return replace(self, items=[merged[k] for k in sorted(merged)], manifest=None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "case_id": self.case_id,
            "collected_at": self.collected_at,
            "execution_report": self.execution_report,
            "remediation_intent": self.remediation_intent,
            "vulnerability_predicate": self.vulnerability_predicate,
            "required_health_checks": list(self.required_health_checks),
            "standing_risk_predicates": self.standing_risk_predicates,
            "items": [i.to_dict() for i in self.items],
            "manifest": self.manifest.to_dict() if self.manifest else None,
        }

    def fingerprint(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
