"""Per-arm behavioural tests."""
from __future__ import annotations

from rvbench.adapters.simulated import SimulatedEndpointAdapter
from rvbench.cases import PublicCase, Scenario
from rvbench.models import Verdict
from rvbench.verifiers import IndependentVerifier, StatusOnlyVerifier, TargetStateVerifier
from rvbench.verifiers.base import VerifierInput


def _predict(entry, verifier):
    case = PublicCase.from_dict(entry["public"])
    adapter = SimulatedEndpointAdapter(Scenario.from_dict(entry["scenario"]))
    adapter.apply_remediation()
    return verifier.run(VerifierInput(case=case, adapter=adapter))


# --------------------------------------------------------------------- Arm A
def test_arm_a_says_safe_on_exit_zero_even_when_nothing_changed(by_id):
    out = _predict(by_id["B-01"], StatusOnlyVerifier())
    assert out.verdict == Verdict.VERIFIED_REMEDIATED.value
    assert "EXIT_CODE_ZERO" in out.reason_codes


def test_arm_a_says_failed_on_nonzero_exit_even_when_actually_fixed(by_id):
    out = _predict(by_id["A-08"], StatusOnlyVerifier())
    assert out.verdict == Verdict.REMEDIATION_FAILED.value


def test_arm_a_never_returns_insufficient_evidence(experiment):
    rows = experiment["rows_by_arm"]["STATUS_ONLY"]
    assert all(r["predicted"] != Verdict.INSUFFICIENT_EVIDENCE.value for r in rows)


# --------------------------------------------------------------------- Arm B
def test_arm_b_catches_exit_zero_no_change(by_id):
    out = _predict(by_id["B-01"], TargetStateVerifier())
    assert out.verdict == Verdict.REMEDIATION_FAILED.value
    assert "TARGET_STATE_NOT_APPLIED" in out.reason_codes


def test_arm_b_ignores_exit_code(by_id):
    """A-08 exits 1 but the target state landed; Arm B must not be fooled."""
    out = _predict(by_id["A-08"], TargetStateVerifier())
    assert out.verdict == Verdict.VERIFIED_REMEDIATED.value


def test_arm_b_is_fooled_by_wrong_target(by_id):
    out = _predict(by_id["C-01"], TargetStateVerifier())
    assert out.verdict == Verdict.VERIFIED_REMEDIATED.value


def test_arm_b_fails_closed_on_missing_evidence(by_id):
    out = _predict(by_id["L-01"], TargetStateVerifier())
    assert out.verdict == Verdict.INSUFFICIENT_EVIDENCE.value


# --------------------------------------------------------------------- Arm C
def test_arm_c_detects_exit_zero_no_change(by_id):
    out = _predict(by_id["B-01"], IndependentVerifier())
    assert out.verdict == Verdict.REMEDIATION_FAILED.value
    assert "VULNERABILITY_PREDICATE_STILL_TRUE" in out.reason_codes


def test_arm_c_detects_non_persistence(by_id):
    out = _predict(by_id["D-01"], IndependentVerifier())
    assert out.verdict == Verdict.REMEDIATION_FAILED.value
    assert "REMEDIATION_NOT_PERSISTENT_ACROSS_REBOOT" in out.reason_codes


def test_arm_c_distinguishes_staged_from_effective(by_id):
    out = _predict(by_id["J-01"], IndependentVerifier())
    assert out.verdict == Verdict.PARTIALLY_REMEDIATED.value
    assert "REMEDIATION_STAGED_PENDING_REBOOT" in out.reason_codes


def test_arm_c_detects_side_by_side(by_id):
    out = _predict(by_id["E-01"], IndependentVerifier())
    assert out.verdict == Verdict.REMEDIATION_FAILED.value
    assert "VULNERABLE_DUPLICATE_INSTALL_PRESENT" in out.reason_codes


def test_arm_c_detects_partial_composite(by_id):
    out = _predict(by_id["F-01"], IndependentVerifier())
    assert out.verdict == Verdict.PARTIALLY_REMEDIATED.value
    assert out.evidence["vulnerable_components"] == ["MACRO_POLICY_INSECURE"]


def test_arm_c_detects_regression(by_id):
    out = _predict(by_id["H-01"], IndependentVerifier())
    assert out.verdict == Verdict.REGRESSION_INTRODUCED.value


def test_arm_c_detects_new_risk(by_id):
    out = _predict(by_id["I-01"], IndependentVerifier())
    assert out.verdict == Verdict.NEW_SECURITY_RISK.value


def test_arm_c_detects_incomplete_rollout(by_id):
    out = _predict(by_id["G-01"], IndependentVerifier())
    assert out.verdict == Verdict.PARTIALLY_REMEDIATED.value
    assert "ROLLOUT_INCOMPLETE" in out.reason_codes


def test_arm_c_never_converts_missing_evidence_into_success(by_id):
    for cid in ("L-01", "L-02", "L-03"):
        out = _predict(by_id[cid], IndependentVerifier())
        assert out.verdict == Verdict.INSUFFICIENT_EVIDENCE.value, cid


def test_arm_c_is_fooled_only_by_silent_blind_spots(experiment):
    """The residual: Arm C's false-safes are exactly the silent-blindness cases."""
    fs = experiment["metrics"]["INDEPENDENT_VERIFIER"]["false_safe_case_ids"]
    assert sorted(fs) == ["E-04", "I-03", "K-03"]


def test_all_arms_emit_only_legal_verdicts(experiment):
    from rvbench.models import ALL_VERDICTS
    for rows in experiment["rows_by_arm"].values():
        for r in rows:
            assert r["predicted"] in ALL_VERDICTS


def test_arm_c_outputs_are_auditable(by_id):
    out = _predict(by_id["E-01"], IndependentVerifier())
    assert 0.0 <= out.confidence <= 1.0
    assert out.reason_codes and all(isinstance(c, str) for c in out.reason_codes)
    assert out.evidence["vulnerable_now_per_device"] == [True]
