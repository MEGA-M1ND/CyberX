"""Classify every (fixture, decisive fact, collector) triple.

In DRY_RUN the classification is deduced from the collector's contract.  In
REAL_LAB it is derived from what the collector actually returned, and the two
are compared - the deltas are the finding a real run exists to produce.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..contracts.catalog import BY_ID
from ..contracts.scope import CollectorContract
from ..fixtures.spec import FixtureSpec
from ..vocab import GapClass, RunStatus


@dataclass(frozen=True)
class Classification:
    fixture_id: str
    family: str
    fact_id: str
    evidence_type: str
    decides: str
    collector_id: str
    gap_class: str
    completeness_claimed: bool
    covered: bool
    status: str
    coordinates: Dict[str, Any]

    @property
    def is_silent_miss(self) -> bool:
        return self.gap_class == GapClass.UNDECLARED_GAP.value

    @property
    def resolved(self) -> bool:
        return self.gap_class == GapClass.NONE.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "family": self.family,
            "fact_id": self.fact_id,
            "evidence_type": self.evidence_type,
            "decides": self.decides,
            "collector_id": self.collector_id,
            "gap_class": self.gap_class,
            "completeness_claimed": self.completeness_claimed,
            "covered": self.covered,
            "status": self.status,
            "coordinates": self.coordinates,
        }


def classify_predicted(fixtures: List[FixtureSpec], collector_ids: List[str]
                       ) -> List[Classification]:
    out: List[Classification] = []
    for fixture in fixtures:
        for collector_id in collector_ids:
            contract: CollectorContract = BY_ID[collector_id]
            for fact in fixture.decisive_facts:
                out.append(Classification(
                    fixture_id=fixture.fixture_id,
                    family=fixture.family,
                    fact_id=fact.fact_id,
                    evidence_type=fact.evidence_type,
                    decides=fact.decides,
                    collector_id=collector_id,
                    gap_class=contract.classify(fact),
                    completeness_claimed=contract.claims_completeness_over(fact),
                    covered=contract.covers(fact),
                    status=RunStatus.PREDICTED_FROM_CONTRACTS.value,
                    coordinates=fact.coordinates.to_dict(),
                ))
    return out


def classify_observed(fixtures: List[FixtureSpec], observations: Dict[str, Dict[str, Any]]
                      ) -> List[Classification]:
    """REAL_LAB path.

    `observations` maps collector_id -> the collector's own JSON output, which
    carries both the facts it resolved and the failures it is willing to admit.
    A decisive fact that is absent from the output and absent from the declared
    failures, on a collector claiming completeness, is an undeclared gap - the
    measurement this whole experiment is for.
    """
    out: List[Classification] = []
    for fixture in fixtures:
        for collector_id, payload in sorted(observations.items()):
            contract = BY_ID[collector_id]
            resolved = {r.get("fact_locator") for r in payload.get("resolved_facts", [])}
            failures = {f.get("locator") for f in payload.get("failures", [])}
            stale = {r.get("fact_locator") for r in payload.get("stale_facts", [])}
            disputed = {r.get("fact_locator") for r in payload.get("disputed_facts", [])}
            wrong_device = payload.get("device_identity_mismatch", False)

            for fact in fixture.decisive_facts:
                if wrong_device:
                    gap = GapClass.WRONG_DEVICE_OR_SCOPE.value
                elif fact.locator in disputed:
                    gap = GapClass.CONTRADICTORY_EVIDENCE.value
                elif fact.locator in stale:
                    gap = GapClass.STALE_EVIDENCE.value
                elif fact.locator in resolved:
                    gap = GapClass.NONE.value
                elif fact.locator in failures:
                    gap = GapClass.COLLECTION_ERROR.value
                elif contract.claims_completeness_over(fact):
                    gap = GapClass.UNDECLARED_GAP.value
                else:
                    gap = GapClass.DECLARED_GAP.value
                out.append(Classification(
                    fixture_id=fixture.fixture_id,
                    family=fixture.family,
                    fact_id=fact.fact_id,
                    evidence_type=fact.evidence_type,
                    decides=fact.decides,
                    collector_id=collector_id,
                    gap_class=gap,
                    completeness_claimed=contract.claims_completeness_over(fact),
                    covered=gap == GapClass.NONE.value,
                    status=RunStatus.MEASURED_ON_LAB_VM.value,
                    coordinates=fact.coordinates.to_dict(),
                ))
    return out


def prediction_vs_measurement(predicted: List[Classification],
                              measured: List[Classification]) -> Dict[str, Any]:
    """The deliverable of a real run: where the contracts were wrong."""
    index = {(c.fixture_id, c.fact_id, c.collector_id): c for c in predicted}
    agree, disagree = 0, []
    for observation in measured:
        key = (observation.fixture_id, observation.fact_id, observation.collector_id)
        prediction = index.get(key)
        if prediction is None:
            continue
        if prediction.gap_class == observation.gap_class:
            agree += 1
        else:
            disagree.append({"key": list(key), "predicted": prediction.gap_class,
                             "measured": observation.gap_class})
    total = agree + len(disagree)
    return {
        "compared": total,
        "agreements": agree,
        "disagreements": len(disagree),
        "agreement_rate": (agree / total) if total else None,
        "detail": disagree[:200],
    }


def resolves_fixture(classifications: List[Classification], fixture_id: str,
                     collector_id: str, questions: Optional[List[str]] = None) -> bool:
    """Did this collector settle every decisive fact for this fixture?"""
    relevant = [c for c in classifications
                if c.fixture_id == fixture_id and c.collector_id == collector_id
                and (questions is None or c.decides in questions)]
    return bool(relevant) and all(c.resolved for c in relevant)
