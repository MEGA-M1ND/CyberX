"""Vulnerability predicate correctness, including three-valued behaviour."""
from __future__ import annotations

from rvbench.models import EvidenceType, Tri
from rvbench.predicates import components, evaluate, required_evidence
from rvbench.simulator.state import EndpointState


def test_package_version_below():
    p = {"op": "package_version_below", "package": "p", "fixed_version": "1.4.5"}
    assert evaluate(p, EndpointState(packages={"p": ["1.4.2"]})) is Tri.TRUE
    assert evaluate(p, EndpointState(packages={"p": ["1.4.5"]})) is Tri.FALSE
    # side-by-side: a fixed build does not cancel a vulnerable one
    assert evaluate(p, EndpointState(packages={"p": ["1.4.2", "1.4.5"]})) is Tri.TRUE


def test_registry_missing_key_is_not_secure():
    p = {"op": "registry_not_equals", "path": "HKLM\\X", "value": 0}
    assert evaluate(p, EndpointState()) is Tri.TRUE
    assert evaluate(p, EndpointState(registry={"HKLM\\X": 0})) is Tri.FALSE


def test_missing_evidence_class_yields_unknown_not_false():
    p = {"op": "package_version_below", "package": "p", "fixed_version": "1.4.5"}
    s = EndpointState(packages={"p": ["1.4.2"]})
    s.available.discard(EvidenceType.PACKAGE_STATE.value)
    assert evaluate(p, s) is Tri.UNKNOWN


def test_three_valued_any_of_and_all_of():
    known_true = {"op": "reboot_pending"}
    unknown = {"op": "package_version_below", "package": "p", "fixed_version": "9"}
    s = EndpointState(reboot_pending=True, packages={"p": ["1"]})
    s.available.discard(EvidenceType.PACKAGE_STATE.value)
    assert evaluate({"op": "any_of", "operands": [known_true, unknown]}, s) is Tri.TRUE
    assert evaluate({"op": "all_of", "operands": [known_true, unknown]}, s) is Tri.UNKNOWN
    s2 = EndpointState(reboot_pending=False, packages={"p": ["1"]})
    s2.available.discard(EvidenceType.PACKAGE_STATE.value)
    assert evaluate({"op": "any_of", "operands": [known_true, unknown]}, s2) is Tri.UNKNOWN
    assert evaluate({"op": "all_of", "operands": [known_true, unknown]}, s2) is Tri.FALSE


def test_not_propagates_unknown():
    unknown = {"op": "package_version_below", "package": "p", "fixed_version": "9"}
    s = EndpointState()
    s.available.discard(EvidenceType.PACKAGE_STATE.value)
    assert evaluate({"op": "not", "operand": unknown}, s) is Tri.UNKNOWN


def test_required_evidence_and_components():
    node = {"op": "any_of", "operands": [
        {"id": "a", "op": "patch_missing", "kb": "KB1"},
        {"id": "b", "op": "file_exists", "path": "x"},
    ]}
    assert required_evidence(node) == {"PATCH_STATE", "FILE_STATE"}
    assert len(components(node)) == 2
    assert len(components({"op": "file_exists", "path": "x"})) == 1


def test_every_corpus_predicate_parses(corpus):
    for entry in corpus:
        pub = entry["public"]
        required_evidence(pub["vulnerability_predicate"])
        for node in pub["remediation_intent"]["target_state_assertions"]:
            required_evidence(node)
