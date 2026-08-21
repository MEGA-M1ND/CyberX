"""Per-arm behaviour, including the cases each arm is supposed to fail."""
from __future__ import annotations

from rv2.collect.collector import EvidenceService
from rv2.oracle.truth import derive_truth
from rv2.verifiers import (
    ActiveEvidenceVerifier,
    ScopeAwareFailClosedVerifier,
    ScopeUnawareIndependentVerifier,
    StatusOnlyVerifier,
    TargetStateVerifier,
    build_arms,
)
from rv2.verifiers.arm_e_active import MAX_REQUESTS
from rv2.vocab import Verdict
from rv2.world.scenarios import FAMILIES, build_world

FLAT = {"A_STATUS_ONLY", "B_TARGET_STATE", "C_SCOPE_UNAWARE_INDEPENDENT"}


def verdict(family, arm, coverage=1.0, mechanism="NONE", seed=11, world_seed=1):
    world = build_world(family, world_seed, "c")
    service = EvidenceService(world, coverage, mechanism, seed)
    package = service.build_package()
    view = package.flat_view() if arm.arm in FLAT else package
    channel = service if arm.arm == "E_ACTIVE_EVIDENCE" else None
    return arm.run(view, channel), derive_truth(world)


# ------------------------------------------------------------------- shared
def test_all_arms_are_correct_when_evidence_is_complete():
    """Nothing separates the independent arms until evidence goes missing."""
    for family in FAMILIES:
        for arm in (ScopeUnawareIndependentVerifier(), ScopeAwareFailClosedVerifier(),
                    ActiveEvidenceVerifier()):
            decision, truth = verdict(family, arm)
            assert decision.verdict == truth.label, (family, arm.arm, decision.verdict)


def test_all_arms_emit_only_legal_verdicts():
    legal = {v.value for v in Verdict}
    for family in FAMILIES:
        for arm in build_arms():
            for mechanism in ("NONE", "DECISIVE_FIELD_MISSING", "UNDECLARED_GAP"):
                decision, _ = verdict(family, arm, 0.6, mechanism)
                assert decision.verdict in legal


# ------------------------------------------------------------------- Arm A
def test_arm_a_blesses_anything_that_exits_zero():
    for family in ("EXIT_ZERO_NO_CHANGE", "SIDE_BY_SIDE_VULNERABLE", "REGRESSION_INTRODUCED"):
        decision, _ = verdict(family, StatusOnlyVerifier())
        assert decision.verdict == Verdict.VERIFIED_REMEDIATED.value


def test_arm_a_never_abstains():
    for family in FAMILIES:
        decision, _ = verdict(family, StatusOnlyVerifier(), 0.4, "RANDOM_MISSING")
        assert decision.verdict != Verdict.INSUFFICIENT_EVIDENCE.value


# ------------------------------------------------------------------- Arm B
def test_arm_b_catches_a_change_that_never_landed():
    decision, _ = verdict("EXIT_ZERO_NO_CHANGE", TargetStateVerifier())
    assert decision.verdict == Verdict.REMEDIATION_FAILED.value


def test_arm_b_is_fooled_when_the_wrong_thing_changed():
    decision, truth = verdict("WRONG_REGISTRY_KEY", TargetStateVerifier())
    assert decision.verdict == Verdict.VERIFIED_REMEDIATED.value
    assert truth.label != decision.verdict


# ------------------------------------------------------------------- Arm C
def test_arm_c_catches_every_family_with_complete_evidence():
    for family in FAMILIES:
        decision, truth = verdict(family, ScopeUnawareIndependentVerifier())
        assert decision.verdict == truth.label


def test_arm_c_is_blind_to_a_narrowed_scope():
    """The v1 failure mode, reproduced: a narrowed inventory reads as clean."""
    decision, truth = verdict("SIDE_BY_SIDE_VULNERABLE", ScopeUnawareIndependentVerifier(),
                              0.8, "DECISIVE_FIELD_MISSING")
    assert decision.verdict == Verdict.VERIFIED_REMEDIATED.value
    assert truth.label == Verdict.REMEDIATION_FAILED.value


def test_arm_c_has_no_manifest():
    world = build_world("GENUINE_REMEDIATION", 1, "c")
    package = EvidenceService(world, 0.8, "DECISIVE_FIELD_MISSING", 3).build_package()
    assert package.flat_view().manifest is None
    assert package.flat_view().covered_scopes(package.items[0]) is None


# ------------------------------------------------------------------- Arm D
def test_arm_d_refuses_when_the_decisive_scope_was_not_queried():
    decision, _ = verdict("SIDE_BY_SIDE_VULNERABLE", ScopeAwareFailClosedVerifier(),
                          0.8, "DECISIVE_FIELD_MISSING")
    assert decision.verdict == Verdict.INSUFFICIENT_EVIDENCE.value
    assert any("SCOPE" in code for code in decision.reason_codes)


def test_arm_d_refuses_on_stale_evidence():
    decision, _ = verdict("GENUINE_REMEDIATION", ScopeAwareFailClosedVerifier(),
                          0.8, "STALE_EVIDENCE")
    assert decision.verdict == Verdict.INSUFFICIENT_EVIDENCE.value


def test_arm_d_refuses_on_contradiction():
    decision, _ = verdict("GENUINE_REMEDIATION", ScopeAwareFailClosedVerifier(),
                          0.8, "CONTRADICTORY_EVIDENCE")
    assert decision.verdict == Verdict.INSUFFICIENT_EVIDENCE.value


def test_arm_d_refuses_when_a_targeted_device_never_reported():
    decision, _ = verdict("GROUP_PARTIAL_ROLLOUT", ScopeAwareFailClosedVerifier(),
                          0.6, "SCOPE_MISMATCH")
    assert decision.verdict != Verdict.VERIFIED_REMEDIATED.value


def test_arm_d_still_reports_a_proven_problem_rather_than_abstaining():
    """Refusing to answer when the evidence already proves the box is unsafe
    would be fail-closed in name and useless in practice."""
    decision, truth = verdict("EXIT_ZERO_NO_CHANGE", ScopeAwareFailClosedVerifier(),
                              0.6, "REGRESSION_EVIDENCE_MISSING")
    assert decision.verdict == Verdict.REMEDIATION_FAILED.value == truth.label


def test_arm_d_is_defeated_by_an_undeclared_gap():
    """The honest limit: a manifest that lies is not a manifest."""
    decision, truth = verdict("SIDE_BY_SIDE_VULNERABLE", ScopeAwareFailClosedVerifier(),
                              0.8, "UNDECLARED_GAP")
    assert decision.verdict == Verdict.VERIFIED_REMEDIATED.value
    assert truth.label == Verdict.REMEDIATION_FAILED.value


def test_arm_d_requires_harm_evidence_before_verifying():
    decision, _ = verdict("GENUINE_REMEDIATION", ScopeAwareFailClosedVerifier(),
                          0.9, "REGRESSION_EVIDENCE_MISSING")
    assert decision.verdict == Verdict.INSUFFICIENT_EVIDENCE.value


# ------------------------------------------------------------------- Arm E
def test_arm_e_requests_are_bounded():
    for family in FAMILIES:
        for mechanism in ("RANDOM_MISSING", "DECISIVE_FIELD_MISSING", "SCOPE_MISMATCH"):
            decision, _ = verdict(family, ActiveEvidenceVerifier(), 0.4, mechanism)
            assert len(decision.evidence_requests) <= MAX_REQUESTS


def test_arm_e_makes_no_requests_when_it_can_already_decide():
    decision, _ = verdict("EXIT_ZERO_NO_CHANGE", ActiveEvidenceVerifier())
    assert decision.evidence_requests == []


def test_arm_e_recovers_a_verdict_arm_d_refuses():
    d_decision, truth = verdict("SIDE_BY_SIDE_VULNERABLE", ScopeAwareFailClosedVerifier(),
                                0.8, "DECISIVE_FIELD_MISSING")
    e_decision, _ = verdict("SIDE_BY_SIDE_VULNERABLE", ActiveEvidenceVerifier(),
                            0.8, "DECISIVE_FIELD_MISSING")
    assert d_decision.verdict == Verdict.INSUFFICIENT_EVIDENCE.value
    assert e_decision.verdict == truth.label
    assert e_decision.evidence_requests


def test_arm_e_does_not_lower_the_bar_when_a_request_is_refused():
    """An unrecoverable gap must still end in an abstention, not a guess."""
    decision, _ = verdict("SIDE_BY_SIDE_VULNERABLE", ActiveEvidenceVerifier(),
                          0.8, "UNDECLARED_GAP")
    assert decision.verdict != Verdict.INSUFFICIENT_EVIDENCE.value or not decision.evidence_requests


def test_arm_e_inherits_arm_d_safety(scored_dev):
    d_rows = [r for r in scored_dev["rows"] if r["arm"] == "D_SCOPE_AWARE_FAIL_CLOSED"]
    e_rows = [r for r in scored_dev["rows"] if r["arm"] == "E_ACTIVE_EVIDENCE"]
    unsafe = {"REMEDIATION_FAILED", "PARTIALLY_REMEDIATED", "NEW_SECURITY_RISK"}
    escapes = lambda rows: sum(1 for r in rows
                               if r["truth"] in unsafe and r["verdict"] == "VERIFIED_REMEDIATED")
    assert escapes(e_rows) <= escapes(d_rows)


def test_active_recovery_creates_no_new_false_assurance(scored_dev):
    assert scored_dev["active_recovery"]["new_false_assurances_created"] == 0
