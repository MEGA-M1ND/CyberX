"""Evidence collector: latent reality in, observation package out.

This is the only component that reads the latent world and writes something a
verifier may see.  It is where every kind of blindness is manufactured, and it
keeps the manufacturing record private - the plan never reaches a package.

The service is also what Arm E talks to when it asks for more evidence.  A
request is granted only if the underlying problem is actually fixable: a timeout
is worth retrying, a denied ACL is not, and a widened query occasionally comes
back still incomplete.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple

from ..obs.observed_predicates import evidence_type_for, field_key_for, required_scopes_for
from ..obs.package import (
    FLEET_DEVICE,
    FULL_SCOPE,
    CollectionFailure,
    CollectionManifest,
    CollectionRequest,
    Contradiction,
    EvidenceItem,
    ObservationPackage,
)
from ..vocab import EvidenceType, FailureReason
from ..world.risk_library import STANDING_RISKS
from ..world.scenarios import KB_SERVICING
from ..world.state import T_BASELINE, T_COLLECTION, DeviceState, LatentWorld, filesystem_root_of, registry_root_of
from .conditions import (
    CONTRADICT,
    DEVICE_OUT,
    DROP,
    PER_DEVICE_EVIDENCE,
    STALE,
    UNDECLARED,
    Cell,
    ConditionPlan,
    build_plan,
)

E = EvidenceType

PRIMARY_COLLECTOR = {"id": "mdm-inventory", "version": "6.4.1"}
SECOND_COLLECTOR = {"id": "vuln-scanner", "version": "12.2.0"}
TIEBREAK_COLLECTOR = {"id": "edr-agent", "version": "3.9.7"}

PARTIAL_GRANT_PROBABILITY = 0.15


def patch_class(kb: str) -> str:
    return "servicing_stack" if kb in KB_SERVICING else "security_update"


def scope_of_fact(evidence_type: str, key: str, payload: Any) -> str:
    if evidence_type == E.PACKAGE_INVENTORY.value:
        return payload.get("install_scope", "machine")
    if evidence_type == E.REGISTRY_STATE.value:
        return registry_root_of(key)
    if evidence_type == E.SERVICE_STATE.value:
        return payload.get("startup_type", "manual")
    if evidence_type == E.FILE_STATE.value:
        return filesystem_root_of(key)
    if evidence_type == E.PATCH_STATE.value:
        return patch_class(key)
    return FULL_SCOPE[evidence_type][0]


def project_state(state: DeviceState, evidence_type: str, covered: Set[str]) -> Dict[str, Any]:
    """The payload a query restricted to `covered` would have returned."""
    if evidence_type == E.PACKAGE_INVENTORY.value:
        return {"packages": [p.to_dict() for p in state.packages if p.install_scope in covered]}
    if evidence_type == E.REGISTRY_STATE.value:
        return {"registry": {k: v for k, v in state.registry.items() if registry_root_of(k) in covered}}
    if evidence_type == E.SERVICE_STATE.value:
        return {"services": {k: dict(v) for k, v in state.services.items()
                             if v.get("startup_type") in covered}}
    if evidence_type == E.FILE_STATE.value:
        return {"files": {k: dict(v) for k, v in state.files.items()
                          if filesystem_root_of(k) in covered}}
    if evidence_type == E.PATCH_STATE.value:
        return {"patches": {k: dict(v) for k, v in state.patches.items() if patch_class(k) in covered}}
    if evidence_type == E.APPLICATION_HEALTH.value:
        return {"application_health": dict(state.application_health)}
    if evidence_type == E.SECURITY_POSTURE.value:
        return {"security_posture": dict(state.security_posture)}
    if evidence_type == E.REBOOT_STATE.value:
        return {"reboot_pending": state.reboot_pending}
    raise ValueError(evidence_type)


def _leaves(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    op = node.get("op")
    if op in ("any_of", "all_of"):
        return [leaf for child in node["operands"] for leaf in _leaves(child)]
    if op == "not":
        return _leaves(node["operand"])
    return [node]


def _vulnerable_fact_for(leaf: Dict[str, Any]) -> Tuple[str, Any]:
    """A fact a second collector could report that makes this leaf read TRUE."""
    op = leaf["op"]
    if op == "package_version_below":
        return ("packages", {"name": leaf["package"], "version": "0.0.1",
                             "install_scope": "per_user", "product_code": "{disputed}"})
    if op in ("registry_not_equals", "registry_equals"):
        return ("registry", (leaf["path"], "__disputed__"))
    if op == "service_running":
        return ("services", (leaf["service"], {"status": "running", "startup_type": "manual"}))
    if op in ("file_version_below", "file_present"):
        return ("files", (leaf["path"], {"exists": True, "version": "0.0.1"}))
    if op == "patch_missing":
        return ("patches", (leaf["kb"], {"installed": False, "staged": False}))
    if op == "posture_flag_true":
        return ("security_posture", (leaf["flag"], True))
    return ("", None)


@dataclass
class RequestOutcome:
    evidence_type: str
    device_id: str
    granted: bool
    reason: str
    repaired_cells: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"evidence_type": self.evidence_type, "device_id": self.device_id,
                "granted": self.granted, "reason": self.reason,
                "repaired_cells": self.repaired_cells}


class EvidenceService:
    """Holds the latent world and the damage plan; serves observation packages."""

    def __init__(self, world: LatentWorld, coverage: float, mechanism: str, seed: int) -> None:
        self.world = world
        self.coverage_target = coverage
        self.mechanism = mechanism
        self.seed = seed
        self.plan: ConditionPlan = build_plan(world, coverage, mechanism, seed)
        self._rng = random.Random(seed ^ 0x5EED)
        self._requests: List[RequestOutcome] = []
        self._request_budget = 0

    # ------------------------------------------------------------------ #
    @property
    def requests(self) -> List[RequestOutcome]:
        return list(self._requests)

    def open_request_budget(self, budget: int) -> None:
        self._request_budget = budget
        self._requests = []

    def request_evidence(self, evidence_type: str, device_id: str) -> RequestOutcome:
        """Arm E's one lever.  Bounded, and honest about what cannot be fixed."""
        if self._request_budget <= 0:
            outcome = RequestOutcome(evidence_type, device_id, False, "REQUEST_BUDGET_EXHAUSTED")
            self._requests.append(outcome)
            return outcome
        self._request_budget -= 1

        targets = [c for c in self.plan.cells
                   if c.evidence_type == evidence_type and c.device_id == device_id
                   and c.as_tuple() in self.plan.degraded]
        if not targets:
            outcome = RequestOutcome(evidence_type, device_id, False, "NOTHING_TO_REPAIR")
            self._requests.append(outcome)
            return outcome

        recoverable = [c for c in targets if self.plan.degraded[c.as_tuple()].recoverable]
        if not recoverable:
            reason = self.plan.degraded[targets[0].as_tuple()].reason
            outcome = RequestOutcome(evidence_type, device_id, False, f"NOT_RECOVERABLE:{reason}")
            self._requests.append(outcome)
            return outcome

        # A widened or repeated query usually works, and sometimes still comes
        # back short.  Leaving one partition unrepaired models that.
        keep_short = (len(recoverable) > 1
                      and self._rng.random() < PARTIAL_GRANT_PROBABILITY)
        repair = recoverable[:-1] if keep_short else recoverable
        for cell in repair:
            self.plan.degraded.pop(cell.as_tuple(), None)
            self.plan.dropped_devices.discard(cell.device_id)

        outcome = RequestOutcome(evidence_type, device_id, True,
                                 "PARTIAL_GRANT" if keep_short else "GRANTED", len(repair))
        self._requests.append(outcome)
        return outcome

    # ------------------------------------------------------------------ #
    def build_package(self) -> ObservationPackage:
        world = self.world
        plan = self.plan
        rng = random.Random(self.seed ^ 0xC0FFEE)

        requested: List[CollectionRequest] = []
        items: List[EvidenceItem] = []
        failed: List[CollectionFailure] = []
        unsupported: List[CollectionFailure] = []
        covered_scope_keys: Dict[str, List[str]] = {}
        freshness: Dict[str, int] = {}
        contradictions: List[Contradiction] = []
        identity_mismatches: List[CollectionFailure] = []
        devices_observed: List[str] = []

        reference_at = world.collected_at
        counter = 0

        def new_id(prefix: str) -> str:
            nonlocal counter
            counter += 1
            return f"{prefix}-{counter:04d}"

        for device_id in world.targeted_device_ids:
            device = world.device(device_id)
            device_seen = False
            for etype in PER_DEVICE_EVIDENCE:
                full = list(FULL_SCOPE[etype])
                requested.append(CollectionRequest(etype, device_id, full))

                buckets = self._buckets(device_id, etype, full)
                if not buckets["actual_fresh"] and not buckets["stale"]:
                    reason = buckets["reason"] or FailureReason.SCOPE_NARROWED.value
                    failure = CollectionFailure(etype, device_id, reason,
                                                "no partition of this evidence type was collected")
                    (unsupported if reason == FailureReason.UNSUPPORTED.value else failed).append(failure)
                    continue

                device_seen = True
                current = device.current
                baseline = device.snapshot_or_current("baseline").state

                if buckets["actual_fresh"]:
                    eid = new_id("ev")
                    items.append(EvidenceItem(
                        eid, etype, device_id, PRIMARY_COLLECTOR["id"], PRIMARY_COLLECTOR["version"],
                        reference_at, project_state(current, etype, set(buckets["actual_fresh"]))))
                    covered_scope_keys[eid] = sorted(buckets["declared_fresh"])
                    freshness[eid] = 0

                if buckets["stale"]:
                    eid = new_id("ev")
                    items.append(EvidenceItem(
                        eid, etype, device_id, PRIMARY_COLLECTOR["id"], PRIMARY_COLLECTOR["version"],
                        T_BASELINE, project_state(baseline, etype, set(buckets["stale"]))))
                    covered_scope_keys[eid] = sorted(buckets["stale"])
                    freshness[eid] = reference_at - T_BASELINE

                if buckets["contradicted"]:
                    eid, disputes = self._contradiction_item(
                        new_id("ev"), etype, device_id, current, buckets, rng, items,
                        covered_scope_keys, freshness, reference_at)
                    contradictions.extend(disputes)

            if device_seen:
                devices_observed.append(device_id)

        # fleet-level evidence
        group_cell = Cell(FLEET_DEVICE, E.GROUP_MEMBERSHIP.value, "group")
        requested.append(CollectionRequest(E.GROUP_MEMBERSHIP.value, FLEET_DEVICE, ["group"]))
        group_degraded = plan.degradation_for(group_cell)
        if group_degraded and group_degraded.kind in (DROP, DEVICE_OUT):
            failed.append(CollectionFailure(E.GROUP_MEMBERSHIP.value, FLEET_DEVICE,
                                            group_degraded.reason, group_degraded.detail))
        else:
            eid = new_id("ev")
            enumerated = list(devices_observed)
            if group_degraded and group_degraded.kind == UNDECLARED:
                enumerated = enumerated[: max(1, len(enumerated) - 1)]
            items.append(EvidenceItem(
                eid, E.GROUP_MEMBERSHIP.value, FLEET_DEVICE, PRIMARY_COLLECTOR["id"],
                PRIMARY_COLLECTOR["version"], reference_at,
                {"devices_enumerated": enumerated}))
            covered_scope_keys[eid] = ["group"]
            freshness[eid] = 0

        # Devices that were targeted but produced nothing at all.
        for device_id in world.targeted_device_ids:
            if device_id not in devices_observed:
                identity_mismatches.append(CollectionFailure(
                    E.GROUP_MEMBERSHIP.value, device_id,
                    FailureReason.DEVICE_NOT_ENUMERATED.value,
                    "targeted device returned no evidence of any kind"))

        manifest = CollectionManifest(
            collector_identities=[PRIMARY_COLLECTOR, SECOND_COLLECTOR],
            requested=requested,
            collected_evidence_ids=[i.evidence_id for i in items],
            failed=failed,
            unsupported=unsupported,
            covered_scope_keys=covered_scope_keys,
            devices_requested=list(world.targeted_device_ids),
            devices_observed=devices_observed,
            declared_group_scope={"targeted": len(world.targeted_device_ids),
                                  "observed": len(devices_observed)},
            remediation_completed_at=world.execution.completed_at,
            reboot_performed_at=(T_COLLECTION - 500) if world.reboot_performed else None,
            reboot_pending_reported=None,
            collection_started_at=reference_at - 10,
            collection_completed_at=reference_at,
            freshness_seconds=freshness,
            contradictions=contradictions,
            identity_mismatches=identity_mismatches,
            declared_coverage=_declared_coverage(requested, covered_scope_keys, failed,
                                                unsupported, contradictions, freshness,
                                                world.execution.completed_at, items),
        )

        return ObservationPackage(
            package_id=f"{world.case_id}-pkg",
            case_id=world.case_id,
            collected_at=reference_at,
            execution_report=world.execution.to_dict(),
            remediation_intent=world.remediation_intent,
            vulnerability_predicate=world.vulnerability_predicate,
            required_health_checks=list(world.required_health_checks),
            standing_risk_predicates=STANDING_RISKS,
            items=items,
            manifest=manifest,
        )

    # ------------------------------------------------------------------ #
    def _buckets(self, device_id: str, etype: str, full: List[str]) -> Dict[str, Any]:
        """Split this evidence type's partitions by what happened to each."""
        actual_fresh: List[str] = []
        declared_fresh: List[str] = []
        stale: List[str] = []
        contradicted: List[str] = []
        reason = ""
        for scope_key in full:
            deg = self.plan.degradation_for(Cell(device_id, etype, scope_key))
            if deg is None:
                actual_fresh.append(scope_key)
                declared_fresh.append(scope_key)
                continue
            reason = reason or deg.reason
            if deg.kind == UNDECLARED:
                declared_fresh.append(scope_key)  # claimed but never actually queried
            elif deg.kind == STALE:
                stale.append(scope_key)
            elif deg.kind == CONTRADICT:
                actual_fresh.append(scope_key)
                declared_fresh.append(scope_key)
                contradicted.append(scope_key)
            # DROP and DEVICE_OUT contribute nothing
        return {"actual_fresh": actual_fresh, "declared_fresh": declared_fresh,
                "stale": stale, "contradicted": contradicted, "reason": reason}

    def _contradiction_item(self, eid: str, etype: str, device_id: str, current: DeviceState,
                            buckets: Dict[str, Any], rng: random.Random,
                            items: List[EvidenceItem], covered: Dict[str, List[str]],
                            freshness: Dict[str, int], reference_at: int
                            ) -> Tuple[str, List[Contradiction]]:
        """A second collector reporting a different, more pessimistic reading."""
        payload = project_state(current, etype, set(buckets["contradicted"]))
        disputes: List[Contradiction] = []

        for leaf in _leaves(self.world.vulnerability_predicate):
            if evidence_type_for(leaf["op"]) != etype:
                continue
            if not (required_scopes_for(leaf) & set(buckets["contradicted"])):
                continue
            bucket, fact = _vulnerable_fact_for(leaf)
            if not bucket:
                continue
            if bucket == "packages":
                payload.setdefault("packages", []).append(fact)
            elif bucket in ("registry", "services", "files", "patches", "security_posture"):
                key, value = fact
                payload.setdefault(bucket, {})[key] = value
            disputes.append(Contradiction(etype, device_id, field_key_for(leaf),
                                          [PRIMARY_COLLECTOR["id"], SECOND_COLLECTOR["id"]],
                                          "scanner and endpoint inventory disagree"))

        # Which feed happens to have refreshed last is not something an operator
        # controls, so it is drawn rather than fixed.
        offset = 5 if rng.random() < 0.5 else -5
        items.append(EvidenceItem(eid, etype, device_id, SECOND_COLLECTOR["id"],
                                  SECOND_COLLECTOR["version"], reference_at + offset, payload))
        covered[eid] = sorted(buckets["contradicted"])
        freshness[eid] = max(0, -offset)
        return eid, disputes


def _declared_coverage(requested, covered, failed, unsupported, contradictions,
                       freshness, reference_at, items) -> float:
    """What fraction of the requested surface the manifest itself accounts for."""
    total = sum(len(r.requested_scope_keys) for r in requested)
    if not total:
        return 1.0
    accounted = 0
    disputed = {(c.evidence_type, c.device_id) for c in contradictions}
    for item in items:
        keys = covered.get(item.evidence_id, [])
        if (item.evidence_type, item.device_id) in disputed:
            continue
        if item.collected_at < reference_at:
            continue
        accounted += len(keys)
    return round(min(1.0, accounted / total), 6)


def collect(world: LatentWorld, coverage: float, mechanism: str, seed: int
            ) -> Tuple[ObservationPackage, EvidenceService]:
    service = EvidenceService(world, coverage, mechanism, seed)
    return service.build_package(), service
