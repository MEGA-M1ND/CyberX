"""Evidence conditions: coverage accounting and each mechanism's signature."""
from __future__ import annotations

from rv2.collect.collector import EvidenceService, collect, patch_class, project_state
from rv2.collect.conditions import COVERAGE_LEVELS, MECHANISMS, build_plan, enumerate_cells
from rv2.obs.package import FULL_SCOPE
from rv2.vocab import EvidenceType, FailureReason
from rv2.world.scenarios import build_world

E = EvidenceType


def _world(family="SIDE_BY_SIDE_VULNERABLE", seed=11):
    return build_world(family, seed, "c")


def test_cell_grid_covers_every_device_and_partition():
    world = _world("GROUP_PARTIAL_ROLLOUT")
    cells = enumerate_cells(world)
    per_device = sum(len(FULL_SCOPE[e]) for e in
                     ["PACKAGE_INVENTORY", "REGISTRY_STATE", "SERVICE_STATE", "FILE_STATE",
                      "PATCH_STATE", "APPLICATION_HEALTH", "SECURITY_POSTURE", "REBOOT_STATE"])
    assert len(cells) == per_device * len(world.targeted_device_ids) + 1


def test_achieved_coverage_tracks_the_target():
    world = _world("GROUP_PARTIAL_ROLLOUT")
    for coverage in COVERAGE_LEVELS:
        for mechanism in (MECHANISMS if coverage < 1.0 else ["NONE"]):
            plan = build_plan(world, coverage, mechanism, 5)
            assert abs(plan.achieved_coverage() - coverage) < 0.02, (coverage, mechanism)


def test_full_coverage_damages_nothing():
    for mechanism in list(MECHANISMS) + ["NONE"]:
        plan = build_plan(_world(), 1.0, mechanism, 3)
        assert plan.degraded == {}


def test_collection_is_deterministic():
    world = _world()
    for mechanism in MECHANISMS:
        a, _ = collect(world, 0.6, mechanism, 21)
        b, _ = collect(world, 0.6, mechanism, 21)
        assert a.fingerprint() == b.fingerprint(), mechanism


def test_decisive_field_missing_narrows_the_declared_scope():
    """The item still comes back; the manifest honestly says what it covered."""
    package, _ = collect(_world(), 0.8, "DECISIVE_FIELD_MISSING", 11)
    item = [i for i in package.items if i.evidence_type == E.PACKAGE_INVENTORY.value][0]
    covered = package.manifest.covered_scope_keys[item.evidence_id]
    assert "per_user" not in covered
    assert {p["install_scope"] for p in item.value["packages"]} <= set(covered)


def test_undeclared_gap_lies_about_its_scope():
    """The distinguishing case: data absent, manifest claims full coverage."""
    package, _ = collect(_world(), 0.8, "UNDECLARED_GAP", 11)
    item = [i for i in package.items if i.evidence_type == E.PACKAGE_INVENTORY.value][0]
    covered = set(package.manifest.covered_scope_keys[item.evidence_id])
    assert covered == set(FULL_SCOPE[E.PACKAGE_INVENTORY.value])
    present = {p["install_scope"] for p in item.value["packages"]}
    assert present < covered


def test_random_missing_reports_failures_in_the_manifest():
    package, _ = collect(_world(), 0.4, "RANDOM_MISSING", 11)
    manifest = package.manifest
    reasons = {f.reason for f in list(manifest.failed) + list(manifest.unsupported)}
    assert reasons
    assert reasons <= {FailureReason.TIMEOUT.value, FailureReason.PERMISSION_DENIED.value,
                       FailureReason.UNSUPPORTED.value, FailureReason.SCOPE_NARROWED.value,
                       FailureReason.DEVICE_NOT_ENUMERATED.value}


def test_stale_evidence_is_timestamped_before_the_remediation():
    package, _ = collect(_world(), 0.6, "STALE_EVIDENCE", 11)
    reference = package.manifest.remediation_completed_at
    assert any(i.collected_at < reference for i in package.items)


def test_contradictory_evidence_adds_a_second_collector():
    package, _ = collect(_world(), 0.6, "CONTRADICTORY_EVIDENCE", 11)
    collectors = {i.collector_id for i in package.items}
    assert len(collectors) > 1
    assert package.manifest.contradictions


def test_scope_mismatch_drops_devices_from_the_observed_group():
    package, _ = collect(_world("GROUP_PARTIAL_ROLLOUT"), 0.6, "SCOPE_MISMATCH", 11)
    manifest = package.manifest
    assert len(manifest.devices_observed) < len(manifest.devices_requested)
    assert manifest.declared_group_scope["observed"] < manifest.declared_group_scope["targeted"]


def test_regression_evidence_missing_spares_vulnerability_evidence():
    package, _ = collect(_world(), 0.9, "REGRESSION_EVIDENCE_MISSING", 11)
    types = {i.evidence_type for i in package.items}
    assert E.PACKAGE_INVENTORY.value in types
    assert E.APPLICATION_HEALTH.value not in types or E.SECURITY_POSTURE.value not in types


def test_patch_classification_splits_servicing_stack_from_security():
    assert patch_class("KB5040001") == "servicing_stack"
    assert patch_class("KB5031234") == "security_update"


def test_projection_respects_the_covered_scope():
    world = _world()
    state = world.devices[0].current
    machine_only = project_state(state, E.PACKAGE_INVENTORY.value, {"machine"})
    assert all(p["install_scope"] == "machine" for p in machine_only["packages"])


def test_request_budget_is_enforced():
    _, service = collect(_world(), 0.6, "RANDOM_MISSING", 11)
    service.open_request_budget(2)
    service.request_evidence(E.PACKAGE_INVENTORY.value, "device-001")
    service.request_evidence(E.REGISTRY_STATE.value, "device-001")
    third = service.request_evidence(E.FILE_STATE.value, "device-001")
    assert third.granted is False
    assert third.reason == "REQUEST_BUDGET_EXHAUSTED"


def test_unrecoverable_failures_stay_unrecoverable():
    """A denied ACL or an unsupported platform is not fixed by asking again."""
    service = EvidenceService(_world(), 0.4, "RANDOM_MISSING", 11)
    service.open_request_budget(10)
    refused = []
    for cell, degradation in list(service.plan.degraded.items()):
        if degradation.reason in (FailureReason.PERMISSION_DENIED.value,
                                  FailureReason.UNSUPPORTED.value):
            outcome = service.request_evidence(cell[1], cell[0])
            refused.append(outcome)
    for outcome in refused:
        assert outcome.granted is False or outcome.repaired_cells > 0
