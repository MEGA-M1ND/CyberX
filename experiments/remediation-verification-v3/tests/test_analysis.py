"""Gap classification and metric arithmetic."""
from __future__ import annotations

from rv3.analysis.classify import (
    Classification,
    classify_observed,
    classify_predicted,
    prediction_vs_measurement,
    resolves_fixture,
)
from rv3.analysis.metrics import (
    cross_collector_rescue,
    decisive_undeclared_gap,
    false_coverage_claim,
    harm_fixture_blessed,
    remaining_false_assurance,
    score,
    unresolved_decisive_facts,
    verification_feasibility,
)
from rv3.contracts.catalog import E_SVC, A, B, D, F
from rv3.fixtures.spec import Coordinates, DecisiveFact
from rv3.vocab import COMPOSITE_COLLECTOR, EvidenceType, GapClass, PathRoot, RegistryView, UserScope

E = EvidenceType


def fact(fact_id="f", etype=E.PACKAGE_INVENTORY.value, **coords):
    return DecisiveFact(fact_id, etype, "loc", Coordinates(**coords))


# ------------------------------------------------------------------ contracts
def test_a_misses_the_thirty_two_bit_view_silently():
    node = fact(registry_view=RegistryView.VIEW_32.value, hive="HKLM",
                user_scope=UserScope.MACHINE.value, provider="arp_wow6432")
    assert A.covers(node) is False
    assert A.classify(node) == GapClass.UNDECLARED_GAP.value


def test_b_misses_the_same_fact_but_declares_it():
    node = fact(registry_view=RegistryView.VIEW_64.value, hive="HKU",
                user_scope=UserScope.OTHER_USER_OFFLINE.value, provider="arp_user")
    assert B.covers(node) is False
    assert B.classify(node) == GapClass.DECLARED_GAP.value


def test_a_and_b_differ_only_in_the_completeness_claim():
    """The whole finding in one assertion."""
    node = fact(registry_view=RegistryView.VIEW_64.value, hive="HKCU",
                user_scope=UserScope.CURRENT_USER.value, provider="arp_user")
    assert A.classify(node) == GapClass.UNDECLARED_GAP.value
    assert B.classify(node) == GapClass.NONE.value


def test_package_coordinates_do_not_constrain_the_file_channel():
    """A file fact tagged 'no package record' must still be readable from disk."""
    node = fact(etype=E.FILE_VERSION.value, path_root=PathRoot.PROGRAM_FILES.value,
                provider="none_portable", user_scope=UserScope.MACHINE.value)
    assert D.covers(node) is True
    assert D.classify(node) == GapClass.NONE.value


def test_file_channel_declares_roots_outside_its_list():
    node = fact(etype=E.FILE_VERSION.value, path_root=PathRoot.NON_STANDARD.value,
                user_scope=UserScope.MACHINE.value)
    assert D.classify(node) == GapClass.DECLARED_GAP.value


def test_permission_denied_becomes_a_collection_error_not_silence():
    node = fact(etype=E.FILE_VERSION.value, path_root=PathRoot.PROGRAM_DATA.value,
                user_scope=UserScope.MACHINE.value, requires_elevated_read=True)
    assert D.classify(node) == GapClass.COLLECTION_ERROR.value


def test_service_channel_genuinely_delivers_what_it_claims():
    node = fact(etype=E.SERVICE_STATE.value, user_scope=UserScope.MACHINE.value)
    assert E_SVC.claims_completeness_over(node)
    assert E_SVC.classify(node) == GapClass.NONE.value


def test_composite_never_reaches_an_unloaded_hive():
    node = fact(registry_view=RegistryView.VIEW_64.value, hive="HKU",
                user_scope=UserScope.OTHER_USER_OFFLINE.value, provider="arp_user")
    assert F.covers(node) is False
    assert F.classify(node) == GapClass.DECLARED_GAP.value


def test_composite_claims_completeness_for_nothing():
    assert F.claims_complete_for == []


# ------------------------------------------------------------------ metrics
def rows(*specs):
    out = []
    for i, (gap, claimed, decides, etype) in enumerate(specs):
        out.append(Classification(
            fixture_id=f"fx-{i}", family="FAM", fact_id=f"f{i}", evidence_type=etype,
            decides=decides, collector_id="X", gap_class=gap, completeness_claimed=claimed,
            covered=gap == GapClass.NONE.value, status="PREDICTED_FROM_CONTRACTS",
            coordinates={}))
    return out


def test_undeclared_gap_denominator_is_claims_not_facts():
    data = rows((GapClass.UNDECLARED_GAP.value, True, "VULNERABILITY", E.PACKAGE_INVENTORY.value),
                (GapClass.DECLARED_GAP.value, False, "VULNERABILITY", E.FILE_VERSION.value),
                (GapClass.NONE.value, True, "VULNERABILITY", E.PACKAGE_INVENTORY.value))
    entry = decisive_undeclared_gap(data)
    assert entry["numerator"] == 1
    assert entry["denominator"] == 2
    assert entry["value"] == 0.5


def test_undeclared_gap_rate_is_undefined_when_nothing_is_claimed():
    data = rows((GapClass.DECLARED_GAP.value, False, "VULNERABILITY", E.FILE_VERSION.value))
    assert decisive_undeclared_gap(data)["value"] is None


def test_unresolved_rate_stays_defined_when_the_gap_rate_does_not():
    """The companion metric that a completeness-claiming-nothing collector cannot game."""
    data = rows((GapClass.DECLARED_GAP.value, False, "VULNERABILITY", E.FILE_VERSION.value),
                (GapClass.NONE.value, False, "VULNERABILITY", E.FILE_VERSION.value))
    assert decisive_undeclared_gap(data)["value"] is None
    assert unresolved_decisive_facts(data)["value"] == 0.5


def test_false_coverage_claim_counts_claims_not_facts():
    data = rows((GapClass.UNDECLARED_GAP.value, True, "VULNERABILITY", E.PACKAGE_INVENTORY.value),
                (GapClass.NONE.value, True, "VULNERABILITY", E.PACKAGE_INVENTORY.value))
    entry = false_coverage_claim(data)
    assert entry["numerator"] == 1 and entry["denominator"] == 2


def test_feasibility_requires_every_decisive_fact(catalog):
    data = rows((GapClass.NONE.value, True, "VULNERABILITY", E.PACKAGE_INVENTORY.value))
    data[0] = Classification(**{**data[0].__dict__, "fixture_id": "fx-0"})
    entry = verification_feasibility(data, catalog[:1])
    assert entry["numerator"] == 1


def test_rescue_excludes_the_composite_from_the_rescuer_set(classifications):
    entry = cross_collector_rescue(classifications)
    assert COMPOSITE_COLLECTOR not in entry["detail"]["rescuing_channel_counts"]


def test_remaining_false_assurance_only_counts_vulnerable_fixtures(catalog, classifications):
    entry = remaining_false_assurance(classifications, catalog)
    assert entry["denominator"] == sum(1 for f in catalog if f.expected_vulnerable)


def test_harm_metric_only_counts_regression_fixtures(catalog, classifications):
    entry = harm_fixture_blessed(classifications, catalog)
    assert entry["denominator"] == sum(1 for f in catalog if f.expected_regression)


def test_every_metric_states_its_denominator(catalog, classifications):
    from rv3.contracts.catalog import ALL_CONTRACTS
    result = score(classifications, catalog, [c.collector_id for c in ALL_CONTRACTS])
    for name, definition in result["metric_definitions"].items():
        assert definition["numerator"] and definition["denominator"], name


def test_scoring_is_deterministic(catalog, classifications):
    from rv3.contracts.catalog import ALL_CONTRACTS
    ids = [c.collector_id for c in ALL_CONTRACTS]
    import json
    first = json.dumps(score(classifications, catalog, ids), sort_keys=True, default=str)
    second = json.dumps(score(classifications, catalog, ids), sort_keys=True, default=str)
    assert first == second


# ------------------------------------------------------------------ observed path
def test_observed_classification_reads_the_collector_output(catalog):
    spec = next(f for f in catalog if f.family == "MACHINE_WIDE_64BIT")
    locator = spec.decisive_facts[0].locator
    observed = classify_observed([spec], {"A_UNINSTALL_REGISTRY": {
        "resolved_facts": [{"fact_locator": locator}], "failures": []}})
    assert observed[0].gap_class == GapClass.NONE.value
    assert observed[0].status == "MEASURED_ON_LAB_VM"


def test_observed_absence_on_a_completeness_claim_is_an_undeclared_gap(catalog):
    spec = next(f for f in catalog if f.family == "MACHINE_WIDE_64BIT")
    observed = classify_observed([spec], {"A_UNINSTALL_REGISTRY": {
        "resolved_facts": [], "failures": []}})
    assert observed[0].gap_class == GapClass.UNDECLARED_GAP.value


def test_observed_absence_that_is_reported_is_a_collection_error(catalog):
    spec = next(f for f in catalog if f.family == "MACHINE_WIDE_64BIT")
    locator = spec.decisive_facts[0].locator
    observed = classify_observed([spec], {"A_UNINSTALL_REGISTRY": {
        "resolved_facts": [], "failures": [{"locator": locator, "reason": "PERMISSION_DENIED"}]}})
    assert observed[0].gap_class == GapClass.COLLECTION_ERROR.value


def test_prediction_versus_measurement_reports_disagreements(catalog):
    spec = next(f for f in catalog if f.family == "MACHINE_WIDE_64BIT")
    predicted = classify_predicted([spec], ["A_UNINSTALL_REGISTRY"])
    measured = classify_observed([spec], {"A_UNINSTALL_REGISTRY": {
        "resolved_facts": [], "failures": []}})
    diff = prediction_vs_measurement(predicted, measured)
    assert diff["compared"] == len(spec.decisive_facts)
    assert diff["disagreements"] == 1
    assert diff["detail"][0]["predicted"] == GapClass.NONE.value


def test_resolves_fixture_requires_all_facts(classifications, catalog):
    spec = catalog[0]
    assert resolves_fixture(classifications, spec.fixture_id, "F_COMPOSITE_ACTIVE") in (True, False)
    assert resolves_fixture(classifications, "no-such-fixture", "F_COMPOSITE_ACTIVE") is False
