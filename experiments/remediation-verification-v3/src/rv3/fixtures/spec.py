"""Fixture specification.

A fixture is a synthetic endpoint state whose *decisive evidence* - the facts a
verifier must resolve to decide whether the endpoint is safe - sits at known
coordinates in the Windows evidence surface.  Coordinates are what make the
experiment work: a collector's contract declares which coordinates it queries,
so whether a decisive fact is reachable is a mechanical question rather than a
judgement.

Nothing here is actually vulnerable.  Every fixture is built from harmless
synthetic packages, copies of an existing benign system binary, registry values
under a dedicated lab namespace, and disposable services and tasks.  The
"vulnerable" state is a version string and a file location, not vulnerable code.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..vocab import EvidenceType, PackageProvider, RegistryView, UserScope

# Everything the provisioner creates lives under these two roots, so cleanup can
# be exhaustive and verifiable.
LAB_FILE_ROOT = r"C:\RV3Lab"
LAB_REGISTRY_ROOT = r"SOFTWARE\RV3Lab"
LAB_ARP_PREFIX = "RV3Lab_"
LAB_SERVICE_PREFIX = "RV3Lab_"
LAB_TASK_PREFIX = "RV3Lab_"
LAB_USER_PREFIX = "rv3lab_"


class Decides(str):
    """Which question a decisive fact answers."""


VULNERABILITY = "VULNERABILITY"
PERSISTENCE = "PERSISTENCE"
REGRESSION = "REGRESSION"


@dataclass(frozen=True)
class Coordinates:
    """Where in the Windows evidence surface a fact lives."""

    registry_view: Optional[str] = None      # RegistryView value
    hive: Optional[str] = None               # HKLM | HKCU | HKU
    user_scope: str = UserScope.MACHINE.value
    path_root: Optional[str] = None          # filesystem root the fact sits under
    provider: Optional[str] = None           # PackageProvider value
    requires_reboot_projection: bool = False
    requires_elevated_read: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DecisiveFact:
    """One fact without which the safety question cannot be answered."""

    fact_id: str
    evidence_type: str
    locator: str
    coordinates: Coordinates
    decides: str = VULNERABILITY
    freshness_sensitive: bool = False
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "evidence_type": self.evidence_type,
            "locator": self.locator,
            "coordinates": self.coordinates.to_dict(),
            "decides": self.decides,
            "freshness_sensitive": self.freshness_sensitive,
            "note": self.note,
        }


@dataclass(frozen=True)
class SetupOp:
    """One harmless, reversible provisioning action."""

    op: str
    args: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"op": self.op, "args": self.args}


SUPPORTED_SETUP_OPS = {
    "new_directory",
    "place_stub_binary",
    "write_registry_value",
    "new_arp_entry",
    "new_service",
    "new_scheduled_task",
    "new_local_user",
    "deny_read_acl",
    "unload_user_hive",
    "touch_inventory_cache",
}


@dataclass(frozen=True)
class FixtureSpec:
    """One lab fixture.

    `family` and every expectation field are ground truth and must never reach a
    collector.  Collectors receive `fixture_id` and a target list only.
    """

    fixture_id: str
    family: str
    title: str
    decisive_facts: List[DecisiveFact]
    expected_vulnerable: bool
    expected_persistent_after_reboot: bool
    expected_regression: bool
    setup_ops: List[SetupOp]
    cleanup_ops: List[SetupOp]
    notes: str = ""

    def facts_deciding(self, question: str) -> List[DecisiveFact]:
        return [f for f in self.decisive_facts if f.decides == question]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "family": self.family,
            "title": self.title,
            "decisive_facts": [f.to_dict() for f in self.decisive_facts],
            "expected_vulnerable": self.expected_vulnerable,
            "expected_persistent_after_reboot": self.expected_persistent_after_reboot,
            "expected_regression": self.expected_regression,
            "setup_ops": [o.to_dict() for o in self.setup_ops],
            "cleanup_ops": [o.to_dict() for o in self.cleanup_ops],
            "notes": self.notes,
        }

    def fixture_hash(self) -> str:
        """Covers everything that defines the fixture, ground truth included."""
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def collector_view(self) -> Dict[str, Any]:
        """The only part of a fixture a collector is allowed to see.

        Targets tell the collector where to look.  They are deliberately the
        *union* of plausible locations rather than the decisive coordinates, so
        pointing a collector at a fixture does not hand it the answer.
        """
        return {
            "fixture_id": self.fixture_id,
            "file_root": LAB_FILE_ROOT,
            "registry_root": LAB_REGISTRY_ROOT,
            "arp_prefix": LAB_ARP_PREFIX,
            "service_prefix": LAB_SERVICE_PREFIX,
            "task_prefix": LAB_TASK_PREFIX,
        }


def validate(spec: FixtureSpec) -> None:
    for op in list(spec.setup_ops) + list(spec.cleanup_ops):
        if op.op not in SUPPORTED_SETUP_OPS:
            raise ValueError(f"{spec.fixture_id}: unsupported op {op.op!r}")
    if not spec.decisive_facts:
        raise ValueError(f"{spec.fixture_id}: no decisive facts")
    seen = set()
    for fact in spec.decisive_facts:
        if fact.fact_id in seen:
            raise ValueError(f"{spec.fixture_id}: duplicate fact {fact.fact_id}")
        seen.add(fact.fact_id)
        if fact.evidence_type not in {e.value for e in EvidenceType}:
            raise ValueError(f"{spec.fixture_id}: bad evidence type {fact.evidence_type}")
        coords = fact.coordinates
        if coords.registry_view and coords.registry_view not in {v.value for v in RegistryView}:
            raise ValueError(f"{spec.fixture_id}: bad registry view")
        if coords.user_scope not in {u.value for u in UserScope}:
            raise ValueError(f"{spec.fixture_id}: bad user scope")
        if coords.provider and coords.provider not in {p.value for p in PackageProvider}:
            raise ValueError(f"{spec.fixture_id}: bad provider")
