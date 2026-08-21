"""Corpus shape, per-category scenario behaviour, and ground-truth consistency."""
from __future__ import annotations

from collections import Counter

from rvbench.adapters.simulated import SimulatedEndpointAdapter
from rvbench.cases import PublicCase, Scenario, load_ground_truth
from rvbench.models import Tri, Verdict
from rvbench.predicates import evaluate
from rvbench.scorer.ground_truth import derive


def _run(entry):
    case = PublicCase.from_dict(entry["public"])
    scenario = Scenario.from_dict(entry["scenario"])
    adapter = SimulatedEndpointAdapter(scenario)
    adapter.apply_remediation()
    return case, scenario, adapter


def _label(entry):
    case, _, adapter = _run(entry)
    verdict, _ = derive(
        case=case,
        true_states=adapter._true_states_all(),
        true_post_reboot=[adapter._true_post_reboot(i) for i in range(adapter.device_count)],
        devices_targeted=adapter.get_execution_result().devices_targeted,
        unavailable_evidence=adapter.unavailable_evidence(),
    )
    return verdict


def test_corpus_size_and_composition(corpus):
    assert len(corpus) == 48
    counts = Counter(c["category"] for c in corpus)
    assert len(counts) == 12
    assert counts["A_GENUINE_SUCCESS"] == 8
    assert min(counts.values()) >= 3


def test_case_ids_unique(corpus):
    ids = [c["public"]["case_id"] for c in corpus]
    assert len(ids) == len(set(ids))


def test_corpus_contains_both_success_and_failure(corpus):
    labels = {c["public"]["case_id"]: _label(c) for c in corpus}
    assert sum(1 for v in labels.values() if v == Verdict.VERIFIED_REMEDIATED.value) == 8
    assert sum(1 for v in labels.values() if v != Verdict.VERIFIED_REMEDIATED.value) == 40


def test_required_health_checks_are_defined_on_every_device(corpus):
    """A missing health check must never masquerade as a passing one."""
    for entry in corpus:
        case = PublicCase.from_dict(entry["public"])
        for state in entry["scenario"]["initial_states"]:
            for check in case.required_health_checks:
                assert check in state["health_checks"], f"{case.case_id}:{check}"


def test_successful_remediation_clears_the_predicate(by_id):
    case, _, adapter = _run(by_id["A-01"])
    assert evaluate(case.vulnerability_predicate, adapter._true_state()) is Tri.FALSE
    assert _label(by_id["A-01"]) == Verdict.VERIFIED_REMEDIATED.value


def test_noop_remediation_leaves_the_endpoint_vulnerable(by_id):
    case, _, adapter = _run(by_id["B-01"])
    assert evaluate(case.vulnerability_predicate, adapter._true_state()) is Tri.TRUE


def test_exit_zero_but_vulnerable(by_id):
    _, scenario, adapter = _run(by_id["B-01"])
    assert adapter.get_execution_result().exit_code == 0
    assert _label(by_id["B-01"]) == Verdict.REMEDIATION_FAILED.value


def test_reboot_persistence_case(by_id):
    case, _, adapter = _run(by_id["D-01"])
    assert evaluate(case.vulnerability_predicate, adapter._true_state()) is Tri.FALSE
    assert evaluate(case.vulnerability_predicate, adapter._true_post_reboot()) is Tri.TRUE
    assert _label(by_id["D-01"]) == Verdict.REMEDIATION_FAILED.value


def test_reboot_required_is_partial_not_failed(by_id):
    case, _, adapter = _run(by_id["J-01"])
    assert evaluate(case.vulnerability_predicate, adapter._true_state()) is Tri.TRUE
    assert evaluate(case.vulnerability_predicate, adapter._true_post_reboot()) is Tri.FALSE
    assert _label(by_id["J-01"]) == Verdict.PARTIALLY_REMEDIATED.value


def test_side_by_side_package(by_id):
    _, _, adapter = _run(by_id["E-01"])
    assert adapter._true_state().packages["AcmeReader"] == ["1.4.2", "1.4.5"]
    assert _label(by_id["E-01"]) == Verdict.REMEDIATION_FAILED.value


def test_partial_composite_remediation(by_id):
    assert _label(by_id["F-01"]) == Verdict.PARTIALLY_REMEDIATED.value


def test_regression_detection_case(by_id):
    assert _label(by_id["H-01"]) == Verdict.REGRESSION_INTRODUCED.value


def test_new_risk_case(by_id):
    assert _label(by_id["I-01"]) == Verdict.NEW_SECURITY_RISK.value


def test_missing_evidence_case(by_id):
    _, _, adapter = _run(by_id["L-01"])
    assert adapter.inspect_packages().available is False
    assert _label(by_id["L-01"]) == Verdict.INSUFFICIENT_EVIDENCE.value


def test_fleet_partial_rollout(by_id):
    _, _, adapter = _run(by_id["G-01"])
    assert adapter.device_count == 7
    assert adapter.get_execution_result().devices_targeted == 10
    assert _label(by_id["G-01"]) == Verdict.PARTIALLY_REMEDIATED.value


def test_silent_blind_spots_are_invisible_but_real(by_id):
    """The three cases where the collector lies by omission."""
    for cid in ("E-04", "I-03", "K-03"):
        case, _, adapter = _run(by_id[cid])
        # honest evidence classes all report as available...
        assert adapter.inspect_packages().available
        assert adapter.inspect_registry().available
        assert adapter.inspect_security_flags().available
        # ...yet the true state and the observed state disagree
        true_state = adapter._true_state()
        observed = adapter._observable()
        assert true_state.fingerprint() != observed.fingerprint(), cid


def test_stored_labels_match_recomputed_labels(root, corpus):
    """The label file is an artefact of derive(), never hand-written."""
    stored = load_ground_truth(root / "cases" / "ground_truth" / "labels.json")
    for entry in corpus:
        cid = entry["public"]["case_id"]
        assert stored[cid].label == _label(entry), cid
        assert stored[cid].category == entry["category"]
