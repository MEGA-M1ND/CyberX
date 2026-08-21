"""Arm D - SCOPE_AWARE_FAIL_CLOSED.

Same question as Arm C, different starting assumption.  Arm C asks "what does
the evidence say?"  Arm D asks "am I entitled to an answer at all?" first, and
only then reads the evidence.

Structurally this is a gate chain, not a cascade: a list of things that must be
justifiable before the word "verified" is available, and a separate, later step
that picks a label once they are.  That shape is deliberately unlike the
oracle's ordered precedence rule - reusing the oracle's shape here is precisely
the coupling v1's report named as its worst threat to validity.

A verdict of VERIFIED_REMEDIATED is refused whenever evidence needed for the
vulnerability predicate, the persistence projection, or the harm checks is
missing, stale, disputed, or outside the scope the collector says it queried.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Tuple

from ..obs.observed_predicates import Blocker, ObsResult, ObsValue, evaluate_scoped
from ..obs.package import FULL_SCOPE, EvidenceItem, ObservationPackage
from ..vocab import EvidenceType, Verdict
from .base import Decision, EvidenceRequestChannel, Verifier

E = EvidenceType

# Which gate a blocker belongs to, in the order Arm E should spend requests.
GATE_PRIORITY = ["VULNERABILITY", "PERSISTENCE", "GROUP_SCOPE", "EXPOSURE", "REGRESSION"]


@dataclass
class ScopedAnalysis:
    verdict: str
    reason_codes: List[str]
    evidence: Dict[str, Any]
    blockers: List[Tuple[str, Blocker]] = field(default_factory=list)

    @property
    def abstained(self) -> bool:
        return self.verdict == Verdict.INSUFFICIENT_EVIDENCE.value


def _components(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(node["operands"]) if node.get("op") == "any_of" else [node]


def _restart_projection(package: ObservationPackage, device_id: str) -> ObservationPackage:
    """A package whose service and patch rows show the post-restart reading.

    Evidence ids are preserved so every manifest scope, freshness, and dispute
    check still applies to the projected rows.
    """
    projected: List[EvidenceItem] = []
    for item in package.items:
        if item.device_id != device_id:
            projected.append(item)
            continue
        if item.evidence_type == E.SERVICE_STATE.value:
            services = {}
            for name, svc in item.value.get("services", {}).items():
                row = dict(svc)
                if svc.get("startup_type") == "automatic":
                    row["status"] = "running"
                elif svc.get("startup_type") == "disabled":
                    row["status"] = "stopped"
                services[name] = row
            projected.append(replace(item, value={"services": services}))
        elif item.evidence_type == E.PATCH_STATE.value:
            patches = {}
            for kb, patch in item.value.get("patches", {}).items():
                row = dict(patch)
                if patch.get("staged"):
                    row["installed"] = True
                    row["staged"] = False
                patches[kb] = row
            projected.append(replace(item, value={"patches": patches}))
        else:
            projected.append(item)
    return replace(package, items=projected)


def _item_usable(package: ObservationPackage, evidence_type: str, device_id: str
                 ) -> Tuple[bool, Optional[Blocker]]:
    """Is there a fresh, in-scope, undisputed item of this type for this device?"""
    manifest = package.manifest
    items = package.items_for(evidence_type, device_id)
    if not items:
        reason = "ITEM_MISSING"
        for failure in list(manifest.failed) + list(manifest.unsupported):
            if failure.evidence_type == evidence_type and failure.device_id == device_id:
                reason = failure.reason
        return False, Blocker(reason, evidence_type, device_id, "requested evidence did not come back")

    reference = manifest.remediation_completed_at
    if manifest.reboot_performed_at is not None:
        reference = max(reference, manifest.reboot_performed_at)

    needed = set(FULL_SCOPE[evidence_type])

    for contradiction in manifest.contradictions:
        if contradiction.evidence_type == evidence_type and contradiction.device_id == device_id:
            return False, Blocker("CONTRADICTED", evidence_type, device_id,
                                  f"{contradiction.field_key} disputed")

    for item in items:
        covered = set(manifest.covered_scope_keys.get(item.evidence_id, []))
        if needed - covered:
            continue
        if item.collected_at < reference:
            continue
        return True, None

    return False, Blocker("SCOPE_NARROWED", evidence_type, device_id,
                          "no fresh, fully-scoped reading available")


def analyse(package: ObservationPackage) -> ScopedAnalysis:
    manifest = package.manifest
    if manifest is None:
        return ScopedAnalysis(Verdict.INSUFFICIENT_EVIDENCE.value,
                              ["NO_COLLECTION_MANIFEST"], {"manifest": None})

    report = package.execution_report
    targeted_ids = list(manifest.devices_requested)
    declared_targets = int(report.get("devices_targeted") or len(targeted_ids))
    evidence: Dict[str, Any] = {
        "devices_targeted_by_delivery": declared_targets,
        "devices_requested": len(targeted_ids),
        "devices_observed": len(manifest.devices_observed),
        "declared_coverage": manifest.declared_coverage,
        "exit_code": report.get("exit_code"),
    }
    blockers: List[Tuple[str, Blocker]] = []

    # ---- gate: the group we were asked about is the group we looked at ----
    if len(targeted_ids) < declared_targets:
        blockers.append(("GROUP_SCOPE", Blocker(
            "GROUP_SCOPE_INCOMPLETE", E.GROUP_MEMBERSHIP.value, "*",
            f"delivery targeted {declared_targets} devices, collection requested {len(targeted_ids)}")))
    for device_id in targeted_ids:
        if device_id not in manifest.devices_observed:
            blockers.append(("GROUP_SCOPE", Blocker(
                "DEVICE_NOT_ENUMERATED", E.GROUP_MEMBERSHIP.value, device_id,
                "targeted device never reported")))

    predicate = package.vulnerability_predicate
    vuln_now: Dict[str, bool] = {}
    vuln_later: Dict[str, bool] = {}

    for device_id in targeted_ids:
        if device_id not in manifest.devices_observed:
            continue
        now: ObsResult = evaluate_scoped(predicate, package, device_id)
        later: ObsResult = evaluate_scoped(predicate, _restart_projection(package, device_id), device_id)
        if now.value is ObsValue.UNRESOLVED:
            blockers.extend(("VULNERABILITY", b) for b in now.blockers)
        if later.value is ObsValue.UNRESOLVED:
            blockers.extend(("PERSISTENCE", b) for b in later.blockers)
        if now.resolved:
            vuln_now[device_id] = now.value is ObsValue.TRUE
        if later.resolved:
            vuln_later[device_id] = later.value is ObsValue.TRUE

        # A restart projection is only trustworthy if we know whether one is
        # pending, so that is part of the persistence gate rather than colour.
        ok, blocker = _item_usable(package, E.REBOOT_STATE.value, device_id)
        if not ok and blocker:
            blockers.append(("PERSISTENCE", blocker))

        ok, blocker = _item_usable(package, E.SECURITY_POSTURE.value, device_id)
        if not ok and blocker:
            blockers.append(("EXPOSURE", blocker))

        ok, blocker = _item_usable(package, E.APPLICATION_HEALTH.value, device_id)
        if not ok and blocker:
            blockers.append(("REGRESSION", blocker))

    evidence["vulnerable_now"] = sorted(d for d, v in vuln_now.items() if v)
    evidence["vulnerable_after_restart"] = sorted(d for d, v in vuln_later.items() if v)
    evidence["blocking_gates"] = sorted({gate for gate, _ in blockers})
    evidence["blockers"] = [b.to_dict() for _, b in blockers[:12]]

    # ---- an observed problem outranks an evidence gap -------------------- #
    # Refusing to answer when the evidence already proves the endpoint is
    # unsafe would be fail-closed in name and useless in practice.
    observed_vulnerable = sorted(d for d in targeted_ids
                                 if vuln_now.get(d) or vuln_later.get(d))
    if observed_vulnerable:
        return _classify_vulnerable(package, targeted_ids, observed_vulnerable,
                                    vuln_now, vuln_later, evidence, blockers)

    if blockers:
        codes = ["EVIDENCE_INSUFFICIENT_FOR_ASSURANCE"] + sorted(
            {f"BLOCKED_{gate}_{b.kind}" for gate, b in blockers})
        return ScopedAnalysis(Verdict.INSUFFICIENT_EVIDENCE.value, codes, evidence, blockers)

    # ---- everything is justifiable; now pick the label ------------------- #
    exposures = _observed(package, targeted_ids, E.SECURITY_POSTURE.value,
                          lambda item, dev: [f"{dev}:{n['id']}" for n in package.standing_risk_predicates
                                             if item.value.get("security_posture", {}).get(n["flag"])])
    if exposures:
        evidence["new_exposures"] = exposures[:8]
        return ScopedAnalysis(Verdict.NEW_SECURITY_RISK.value,
                              ["TARGET_CONDITION_RESOLVED", "NEW_EXPOSURE_CONFIRMED"], evidence)

    broken = _observed(package, targeted_ids, E.APPLICATION_HEALTH.value,
                       lambda item, dev: [f"{dev}:{c}" for c in package.required_health_checks
                                          if item.value.get("application_health", {}).get(c) is False])
    if broken:
        evidence["failing_health_checks"] = broken[:8]
        return ScopedAnalysis(Verdict.REGRESSION_INTRODUCED.value,
                              ["TARGET_CONDITION_RESOLVED", "REQUIRED_HEALTH_CHECK_FAILING"], evidence)

    return ScopedAnalysis(Verdict.VERIFIED_REMEDIATED.value,
                          ["VULNERABILITY_PREDICATE_FALSE_IN_FULL_SCOPE",
                           "PERSISTENT_ACROSS_RESTART_PROJECTION",
                           "EVIDENCE_FRESH_AND_UNDISPUTED",
                           "NO_EXPOSURE_CONFIRMED", "NO_REGRESSION_CONFIRMED",
                           "ROLLOUT_FULLY_CONFIRMED"], evidence)


def _observed(package: ObservationPackage, device_ids: List[str], evidence_type: str, extract):
    out: List[str] = []
    for device_id in device_ids:
        item = package.latest_item(evidence_type, device_id)
        if item is None:
            continue
        out.extend(extract(item, device_id))
    return out


def _classify_vulnerable(package, targeted_ids, affected, vuln_now, vuln_later, evidence, blockers):
    reasons = ["VULNERABILITY_PREDICATE_STILL_TRUE"]
    if blockers:
        reasons.append("EVIDENCE_GAPS_PRESENT_BUT_ENDPOINT_ALREADY_PROVEN_UNSAFE")
    if len(affected) < len(targeted_ids):
        return ScopedAnalysis(Verdict.PARTIALLY_REMEDIATED.value,
                              reasons + ["SUBSET_OF_GROUP_STILL_VULNERABLE"], evidence, blockers)
    parts = _components(package.vulnerability_predicate)
    first = affected[0]
    if len(parts) > 1:
        outstanding = []
        for part in parts:
            a = evaluate_scoped(part, package, first)
            b = evaluate_scoped(part, _restart_projection(package, first), first)
            if ObsValue.TRUE in (a.value, b.value):
                outstanding.append(part.get("id", part.get("op")))
        evidence["outstanding_components"] = outstanding
        if 0 < len(outstanding) < len(parts):
            return ScopedAnalysis(Verdict.PARTIALLY_REMEDIATED.value,
                                  reasons + ["COMPOSITE_PARTIALLY_REMEDIATED"], evidence, blockers)
    if not vuln_now.get(first, False) and vuln_later.get(first, False):
        return ScopedAnalysis(Verdict.REMEDIATION_FAILED.value,
                              reasons + ["NOT_PERSISTENT_ACROSS_RESTART"], evidence, blockers)
    if vuln_now.get(first, False) and not vuln_later.get(first, True):
        return ScopedAnalysis(Verdict.PARTIALLY_REMEDIATED.value,
                              reasons + ["STAGED_PENDING_RESTART"], evidence, blockers)
    return ScopedAnalysis(Verdict.REMEDIATION_FAILED.value, reasons, evidence, blockers)


class ScopeAwareFailClosedVerifier(Verifier):
    arm = "D_SCOPE_AWARE_FAIL_CLOSED"
    needs_manifest = True

    def decide(self, package: ObservationPackage,
               channel: Optional[EvidenceRequestChannel] = None) -> Decision:
        analysis = analyse(package)
        confidence = 0.9 if not analysis.abstained else 0.85
        return Decision(analysis.verdict, confidence, analysis.reason_codes, analysis.evidence)
