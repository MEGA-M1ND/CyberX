"""Evidence conditions: the independent variable of this experiment.

The collection surface is modelled as a grid of *cells*, one per
(device, evidence type, scope partition).  A cell is satisfied when the query
that would cover it actually ran, came back after the last event that could
have changed the answer, and is not disputed by a second collector.

    achieved coverage = satisfied cells / total cells

Every mechanism degrades cells until the target coverage is reached.  What
separates them is *which* cells they pick and *how the manifest describes the
loss*:

    RANDOM_MISSING               uniform random cells; the manifest says so
    DECISIVE_FIELD_MISSING       the partition holding the decisive fact, first;
                                 the manifest honestly declares the narrowed scope
    REGRESSION_EVIDENCE_MISSING  health and posture first; vulnerability evidence
                                 is protected until the budget forces a spill
    STALE_EVIDENCE               cells answered from a pre-remediation snapshot
    CONTRADICTORY_EVIDENCE       a second collector disputes the cell
    SCOPE_MISMATCH               whole devices drop out of the observed group,
                                 then install-set partitions narrow
    UNDECLARED_GAP               the data is missing and the manifest claims full
                                 coverage anyway

UNDECLARED_GAP is not in the original v2 brief.  It is here because v1's three
residual failures were all of exactly this shape, and without it this experiment
would be testing scope awareness only against gaps that politely announce
themselves.  It is the control that keeps the headline result honest.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..obs.package import FLEET_DEVICE, FULL_SCOPE
from ..vocab import EvidenceType, FailureReason, Mechanism
from ..world.state import LatentWorld

E = EvidenceType

COVERAGE_LEVELS: Tuple[float, ...] = (1.00, 0.90, 0.80, 0.60, 0.40)

MECHANISMS: Tuple[str, ...] = (
    Mechanism.RANDOM_MISSING.value,
    Mechanism.DECISIVE_FIELD_MISSING.value,
    Mechanism.REGRESSION_EVIDENCE_MISSING.value,
    Mechanism.STALE_EVIDENCE.value,
    Mechanism.CONTRADICTORY_EVIDENCE.value,
    Mechanism.SCOPE_MISMATCH.value,
    "UNDECLARED_GAP",
)

PER_DEVICE_EVIDENCE = [
    E.PACKAGE_INVENTORY.value,
    E.REGISTRY_STATE.value,
    E.SERVICE_STATE.value,
    E.FILE_STATE.value,
    E.PATCH_STATE.value,
    E.APPLICATION_HEALTH.value,
    E.SECURITY_POSTURE.value,
    E.REBOOT_STATE.value,
]
FLEET_EVIDENCE = [E.GROUP_MEMBERSHIP.value]

VULNERABILITY_EVIDENCE = {
    E.PACKAGE_INVENTORY.value, E.REGISTRY_STATE.value, E.SERVICE_STATE.value,
    E.FILE_STATE.value, E.PATCH_STATE.value,
}
HARM_EVIDENCE = {E.APPLICATION_HEALTH.value, E.SECURITY_POSTURE.value}

# How a degraded cell manifests.
DROP = "DROP"                 # scope partition not queried, manifest says so
UNDECLARED = "UNDECLARED"     # data absent, manifest claims it was queried
STALE = "STALE"               # answered from the pre-remediation snapshot
CONTRADICT = "CONTRADICT"     # a second collector disputes it
DEVICE_OUT = "DEVICE_OUT"     # the whole device never reported


@dataclass(frozen=True)
class Cell:
    device_id: str
    evidence_type: str
    scope_key: str

    def as_tuple(self) -> Tuple[str, str, str]:
        return (self.device_id, self.evidence_type, self.scope_key)


@dataclass
class Degradation:
    kind: str
    reason: str = ""
    recoverable: bool = False
    detail: str = ""


@dataclass
class ConditionPlan:
    """The full, private description of how this collection will be damaged."""

    coverage_target: float
    mechanism: str
    cells: List[Cell]
    degraded: Dict[Tuple[str, str, str], Degradation] = field(default_factory=dict)
    dropped_devices: Set[str] = field(default_factory=set)
    seed: int = 0

    def degradation_for(self, cell: Cell) -> Optional[Degradation]:
        return self.degraded.get(cell.as_tuple())

    def satisfied_cells(self) -> int:
        return len(self.cells) - len(self.degraded)

    def achieved_coverage(self) -> float:
        return self.satisfied_cells() / len(self.cells) if self.cells else 1.0


def enumerate_cells(world: LatentWorld) -> List[Cell]:
    cells: List[Cell] = []
    for device_id in world.targeted_device_ids:
        for etype in PER_DEVICE_EVIDENCE:
            for scope_key in FULL_SCOPE[etype]:
                cells.append(Cell(device_id, etype, scope_key))
    for etype in FLEET_EVIDENCE:
        for scope_key in FULL_SCOPE[etype]:
            cells.append(Cell(FLEET_DEVICE, etype, scope_key))
    return cells


def _decisive_cells(world: LatentWorld, cells: List[Cell]) -> List[Cell]:
    hint = world.decisive_hint
    etype, device_id, scope_key = hint.get("evidence_type"), hint.get("device_id"), hint.get("scope_key")
    if etype == E.GROUP_MEMBERSHIP.value:
        return [c for c in cells if c.evidence_type == etype]
    return [c for c in cells
            if c.evidence_type == etype and c.device_id == device_id and c.scope_key == scope_key]


def _reason_cycle(rng: random.Random) -> str:
    return rng.choice([FailureReason.TIMEOUT.value,
                       FailureReason.PERMISSION_DENIED.value,
                       FailureReason.UNSUPPORTED.value])


def _recoverable_for(reason: str, rng: random.Random) -> bool:
    """Whether a follow-up request could actually fix this.

    Grounded in what the failure means rather than a flat probability: a timeout
    is worth retrying, a denied ACL is not, an unsupported platform never will
    be.  Scope widening and re-collection usually work; a tie-break needs a third
    source that may not exist.
    """
    if reason == FailureReason.TIMEOUT.value:
        return True
    if reason in (FailureReason.PERMISSION_DENIED.value, FailureReason.UNSUPPORTED.value):
        return False
    if reason == FailureReason.SCOPE_NARROWED.value:
        return rng.random() < 0.70
    if reason == FailureReason.STALE.value:
        return rng.random() < 0.90
    if reason == FailureReason.CONTRADICTED.value:
        return rng.random() < 0.50
    if reason == FailureReason.DEVICE_NOT_ENUMERATED.value:
        return rng.random() < 0.30
    return False


def build_plan(world: LatentWorld, coverage: float, mechanism: str, seed: int) -> ConditionPlan:
    rng = random.Random(seed)
    cells = enumerate_cells(world)
    plan = ConditionPlan(coverage_target=coverage, mechanism=mechanism, cells=cells, seed=seed)
    if coverage >= 1.0 or mechanism == Mechanism.NONE.value:
        return plan

    budget = len(cells) - int(round(coverage * len(cells)))
    if budget <= 0:
        return plan

    decisive = _decisive_cells(world, cells)
    order = _priority_order(world, cells, decisive, mechanism, rng)

    for cell in order:
        if len(plan.degraded) >= budget:
            break
        if cell.as_tuple() in plan.degraded:
            continue
        _apply(plan, cell, mechanism, rng)

    return plan


def _priority_order(world: LatentWorld, cells: List[Cell], decisive: List[Cell],
                    mechanism: str, rng: random.Random) -> List[Cell]:
    """Which cells this mechanism reaches for first."""
    rest = [c for c in cells if c not in decisive]
    rng.shuffle(rest)

    if mechanism == Mechanism.RANDOM_MISSING.value:
        shuffled = list(cells)
        rng.shuffle(shuffled)
        return shuffled

    if mechanism == Mechanism.REGRESSION_EVIDENCE_MISSING.value:
        harm = [c for c in cells if c.evidence_type in HARM_EVIDENCE]
        neutral = [c for c in rest if c.evidence_type not in HARM_EVIDENCE
                   and c.evidence_type not in VULNERABILITY_EVIDENCE]
        vuln = [c for c in rest if c.evidence_type in VULNERABILITY_EVIDENCE]
        rng.shuffle(harm)
        return harm + neutral + vuln

    if mechanism == Mechanism.SCOPE_MISMATCH.value:
        # Whole devices first (tail of the group), then install-set partitions.
        by_device: Dict[str, List[Cell]] = {}
        for c in cells:
            by_device.setdefault(c.device_id, []).append(c)
        tail = [d for d in world.targeted_device_ids[::-1] if d != world.targeted_device_ids[0]]
        ordered: List[Cell] = []
        for device_id in tail:
            ordered.extend(by_device.get(device_id, []))
        ordered.extend(decisive)
        ordered.extend([c for c in rest if c not in ordered])
        return ordered

    return decisive + rest


def _apply(plan: ConditionPlan, cell: Cell, mechanism: str, rng: random.Random) -> None:
    key = cell.as_tuple()

    if mechanism == Mechanism.RANDOM_MISSING.value:
        reason = _reason_cycle(rng)
        plan.degraded[key] = Degradation(DROP, reason, _recoverable_for(reason, rng),
                                         "cell not covered by any successful query")
        return

    if mechanism in (Mechanism.DECISIVE_FIELD_MISSING.value,
                     Mechanism.REGRESSION_EVIDENCE_MISSING.value):
        reason = FailureReason.SCOPE_NARROWED.value
        plan.degraded[key] = Degradation(DROP, reason, _recoverable_for(reason, rng),
                                         "collection scope did not include this partition")
        return

    if mechanism == Mechanism.STALE_EVIDENCE.value:
        reason = FailureReason.STALE.value
        plan.degraded[key] = Degradation(STALE, reason, _recoverable_for(reason, rng),
                                         "answered from the pre-remediation snapshot")
        return

    if mechanism == Mechanism.CONTRADICTORY_EVIDENCE.value:
        reason = FailureReason.CONTRADICTED.value
        plan.degraded[key] = Degradation(CONTRADICT, reason, _recoverable_for(reason, rng),
                                         "a second collector reports a different value")
        return

    if mechanism == Mechanism.SCOPE_MISMATCH.value:
        if cell.device_id != FLEET_DEVICE and cell.device_id in plan.dropped_devices:
            reason = FailureReason.DEVICE_NOT_ENUMERATED.value
        elif cell.device_id != FLEET_DEVICE and _whole_device_available(plan, cell):
            plan.dropped_devices.add(cell.device_id)
            reason = FailureReason.DEVICE_NOT_ENUMERATED.value
        else:
            reason = FailureReason.SCOPE_NARROWED.value
        plan.degraded[key] = Degradation(
            DEVICE_OUT if reason == FailureReason.DEVICE_NOT_ENUMERATED.value else DROP,
            reason, _recoverable_for(reason, rng),
            "device never reported" if reason == FailureReason.DEVICE_NOT_ENUMERATED.value
            else "installation-set scope narrower than the targeted set")
        return

    if mechanism == "UNDECLARED_GAP":
        plan.degraded[key] = Degradation(UNDECLARED, FailureReason.SCOPE_NARROWED.value, False,
                                         "collector reported full coverage it did not have")
        return

    raise ValueError(f"unknown mechanism {mechanism!r}")


def _whole_device_available(plan: ConditionPlan, cell: Cell) -> bool:
    """Only take a device out if it is not the last one still reporting."""
    devices = {c.device_id for c in plan.cells if c.device_id != FLEET_DEVICE}
    remaining = devices - plan.dropped_devices
    return len(remaining) > 1
