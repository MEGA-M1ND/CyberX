"""Mechanical derivation of the ground-truth label from the TRUE endpoint state.

Ground truth is not hand-written prose: it is computed from the simulator's
private post-remediation state by a single documented precedence rule.  The
stored label file is an artefact of this function, and a test asserts the two
agree for every case.  That removes "the author labelled it that way" as an
explanation for any result.

Precedence (highest first):
  1. INSUFFICIENT_EVIDENCE - a required evidence class is genuinely
     uncollectable, so no honest verifier could assert remediation.
  2. Vulnerability state (security dominates functionality):
       still vulnerable now and after reboot  -> FAILED, or PARTIALLY if the
         composite predicate has some-but-not-all components fixed, or
         PARTIALLY if only some fleet devices are affected
       clean now, vulnerable after reboot     -> FAILED (not persistent)
       vulnerable now, clean after reboot     -> PARTIALLY (staged)
  3. NEW_SECURITY_RISK - the fix landed but left a new unsafe configuration.
  4. REGRESSION_INTRODUCED - the fix landed but broke a required application.
  5. PARTIALLY_REMEDIATED - rollout did not reach every targeted device.
  6. VERIFIED_REMEDIATED.
"""
from __future__ import annotations

from typing import List, Set, Tuple

from ..cases import STANDING_RISK_PREDICATES, PublicCase
from ..models import EvidenceType, Tri, Verdict
from ..predicates import components, evaluate, required_evidence
from ..simulator.state import EndpointState


def required_evidence_for_case(case: PublicCase) -> Set[str]:
    req = set(required_evidence(case.vulnerability_predicate))
    req.add(EvidenceType.EXECUTION_STATUS.value)
    req.add(EvidenceType.REBOOT_STATE.value)
    if case.required_health_checks:
        req.add(EvidenceType.SMOKE_TEST.value)
    if case.fleet_size > 1:
        req.add(EvidenceType.FLEET_COVERAGE.value)
    # The standing risk library is always consulted.
    req.add(EvidenceType.SECURITY_PREDICATE.value)
    return req


def first_true_risk(state: EndpointState) -> str:
    for node in STANDING_RISK_PREDICATES:
        if evaluate(node, state) is Tri.TRUE:
            return node["id"]
    return ""


def failing_health_checks(case: PublicCase, state: EndpointState) -> List[str]:
    return [c for c in case.required_health_checks if state.health_checks.get(c) is False]


def derive(
    case: PublicCase,
    true_states: List[EndpointState],
    true_post_reboot: List[EndpointState],
    devices_targeted: int,
    unavailable_evidence: List[str],
) -> Tuple[str, str]:
    """Returns (verdict, rationale)."""
    required = required_evidence_for_case(case)
    missing = sorted(required & set(unavailable_evidence))
    if missing:
        return (
            Verdict.INSUFFICIENT_EVIDENCE.value,
            f"required evidence unavailable: {', '.join(missing)}",
        )

    pred = case.vulnerability_predicate
    vuln_now = [evaluate(pred, s) is Tri.TRUE for s in true_states]
    vuln_after = [evaluate(pred, s) is Tri.TRUE for s in true_post_reboot]

    enumerated = len(true_states)
    affected = [i for i in range(enumerated) if vuln_now[i] or vuln_after[i]]
    rollout_incomplete = enumerated < devices_targeted

    if affected:
        if 0 < len(affected) < enumerated:
            return (
                Verdict.PARTIALLY_REMEDIATED.value,
                f"{len(affected)}/{enumerated} enumerated devices remain vulnerable",
            )
        # Whole-population failure on device 0's terms.
        comps = components(pred)
        if len(comps) > 1:
            still_true = [c for c in comps if evaluate(c, true_states[0]) is Tri.TRUE or evaluate(c, true_post_reboot[0]) is Tri.TRUE]
            if 0 < len(still_true) < len(comps):
                ids = [c.get("id", "?") for c in still_true]
                return (
                    Verdict.PARTIALLY_REMEDIATED.value,
                    f"composite predicate partly remediated; still true: {', '.join(ids)}",
                )
        if not vuln_now[0] and vuln_after[0]:
            return (
                Verdict.REMEDIATION_FAILED.value,
                "vulnerable condition returns after reboot (remediation not persistent)",
            )
        if vuln_now[0] and not vuln_after[0]:
            return (
                Verdict.PARTIALLY_REMEDIATED.value,
                "remediation staged only; endpoint remains vulnerable until reboot",
            )
        return (Verdict.REMEDIATION_FAILED.value, "vulnerability predicate still true after remediation")

    for idx, s in enumerate(true_states):
        risk = first_true_risk(s)
        if risk:
            return (
                Verdict.NEW_SECURITY_RISK.value,
                f"remediation resolved the target condition but introduced {risk} on device {idx}",
            )

    for idx, s in enumerate(true_states):
        broken = failing_health_checks(case, s)
        if broken:
            return (
                Verdict.REGRESSION_INTRODUCED.value,
                f"required health checks failing on device {idx}: {', '.join(broken)}",
            )

    if rollout_incomplete:
        return (
            Verdict.PARTIALLY_REMEDIATED.value,
            f"only {enumerated}/{devices_targeted} targeted devices could be confirmed remediated",
        )

    return (Verdict.VERIFIED_REMEDIATED.value, "vulnerability predicate false, persistent, no regression, no new risk, full rollout")
