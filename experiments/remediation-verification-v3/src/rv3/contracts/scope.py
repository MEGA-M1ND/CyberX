"""The collector contract.

Every collector must declare, in machine-readable form, the coordinates it
queries and - separately - what it claims to be *complete* for.  Those two
declarations are what let a decisive fact outside a collector's reach be
classified without judgement:

    outside reach, completeness not claimed  ->  DECLARED_GAP
    outside reach, completeness claimed      ->  UNDECLARED_GAP

v2 showed that a scope-aware verifier defends perfectly against the first and
not at all against the second.  So the interesting property of a real collector
is not how much it covers - it is whether its completeness claim is true.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from ..fixtures.spec import DecisiveFact
from ..vocab import EvidenceType, GapClass


class ContractBasis(str):
    """How much the contract is worth."""


IMPLEMENTED_HERE = "IMPLEMENTED_IN_THIS_REPOSITORY"
VENDOR_DOC_MODEL = "MODEL_OF_VENDOR_DOCUMENTATION_UNVERIFIED"


@dataclass(frozen=True)
class CollectorContract:
    collector_id: str
    version: str
    description: str
    mechanism: str
    basis: str
    evidence_types: List[str]
    registry_views: List[str] = field(default_factory=list)
    hives: List[str] = field(default_factory=list)
    user_scopes: List[str] = field(default_factory=list)
    path_roots: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    # The load-bearing field.  Evidence types this collector presents as a
    # complete picture rather than a partial one.
    claims_complete_for: List[str] = field(default_factory=list)
    declared_exclusions: List[str] = field(default_factory=list)
    reports_collection_failures: bool = True
    emits_timestamps: bool = True
    requires_elevation: bool = False
    reads_only: bool = True
    can_widen_scope_on_request: bool = False
    approximate_seconds: float = 1.0
    approximate_records: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    # ------------------------------------------------------------------ #
    def covers(self, fact: DecisiveFact) -> bool:
        """Would a correct implementation of this contract reach the fact?

        Each coordinate constrains only the channels it is a coordinate *of*.  A
        file fact carrying `provider=none_portable` is recording that no package
        record exists for it - that is a statement about the package channel, and
        it must not stop a filesystem channel from reading the file.
        """
        coords = fact.coordinates
        etype = fact.evidence_type
        if etype not in self.evidence_types:
            return False
        if coords.user_scope not in self.user_scopes:
            return False
        if coords.requires_elevated_read and not self.requires_elevation:
            return False

        registry_like = etype in (EvidenceType.PACKAGE_INVENTORY.value,
                                  EvidenceType.REGISTRY_VALUE.value)
        if registry_like:
            if coords.registry_view and coords.registry_view not in self.registry_views:
                return False
            if coords.hive and coords.hive not in self.hives:
                return False
        if etype == EvidenceType.PACKAGE_INVENTORY.value:
            if coords.provider and coords.provider not in self.providers:
                return False
        if etype in (EvidenceType.FILE_PRESENCE.value, EvidenceType.FILE_VERSION.value):
            if coords.path_root and coords.path_root not in self.path_roots:
                return False
        return True

    def claims_completeness_over(self, fact: DecisiveFact) -> bool:
        return fact.evidence_type in self.claims_complete_for

    def classify(self, fact: DecisiveFact) -> str:
        """Gap class for one decisive fact under this contract.

        This is a deduction from the contract, not an observation.  A real run
        replaces it with what the collector actually returned.
        """
        if self.covers(fact):
            return GapClass.NONE.value
        if fact.coordinates.requires_elevated_read and not self.requires_elevation:
            # An access failure the collector can see and report is declared.
            return (GapClass.COLLECTION_ERROR.value if self.reports_collection_failures
                    else GapClass.UNDECLARED_GAP.value)
        if self.claims_completeness_over(fact):
            return GapClass.UNDECLARED_GAP.value
        return GapClass.DECLARED_GAP.value


def contract_hash_payload(contracts: List[CollectorContract]) -> List[Dict[str, Any]]:
    return [c.to_dict() for c in sorted(contracts, key=lambda c: c.collector_id)]
