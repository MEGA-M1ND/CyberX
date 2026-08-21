"""Fixture catalog: coverage of the required families, determinism, hashing."""
from __future__ import annotations

from collections import Counter

from rv3.fixtures.catalog import INSTANCES_PER_FAMILY, build_catalog
from rv3.fixtures.manifest import build_fixture_manifest, provisioning_plan, sha256_json
from rv3.fixtures.spec import LAB_ARP_PREFIX, LAB_FILE_ROOT, SUPPORTED_SETUP_OPS, validate
from rv3.vocab import FAMILIES, EvidenceType


def test_at_least_forty_fixtures_across_the_twenty_required_families(catalog):
    assert len(catalog) >= 40
    assert {f.family for f in catalog} == set(FAMILIES)
    counts = Counter(f.family for f in catalog)
    assert set(counts.values()) == {INSTANCES_PER_FAMILY}


def test_every_fixture_defines_the_required_properties(catalog):
    for spec in catalog:
        validate(spec)
        assert spec.decisive_facts
        assert isinstance(spec.expected_vulnerable, bool)
        assert isinstance(spec.expected_persistent_after_reboot, bool)
        assert isinstance(spec.expected_regression, bool)
        assert spec.setup_ops or spec.cleanup_ops
        assert spec.fixture_hash()


def test_fixture_ids_are_unique_and_opaque(catalog):
    ids = [f.fixture_id for f in catalog]
    assert len(set(ids)) == len(ids)
    for spec in catalog:
        assert spec.fixture_id.startswith("fx-")
        assert spec.family.lower() not in spec.fixture_id.lower()


def test_catalog_is_deterministic():
    first, second = build_catalog(), build_catalog()
    assert [s.to_dict() for s in first] == [s.to_dict() for s in second]
    assert [s.fixture_hash() for s in first] == [s.fixture_hash() for s in second]


def test_fixture_hash_changes_when_ground_truth_changes(catalog):
    import dataclasses
    original = catalog[0]
    edited = dataclasses.replace(original, expected_vulnerable=not original.expected_vulnerable)
    assert edited.fixture_hash() != original.fixture_hash()


def test_corpus_contains_both_vulnerable_and_safe_fixtures(catalog):
    assert sum(1 for f in catalog if f.expected_vulnerable) > 0
    assert sum(1 for f in catalog if not f.expected_vulnerable) > 0


def test_corpus_contains_regression_fixtures(catalog):
    regression = [f for f in catalog if f.expected_regression]
    assert regression
    for spec in regression:
        assert any(f.evidence_type == EvidenceType.APPLICATION_HEALTH.value
                   for f in spec.decisive_facts)


def test_persistence_families_declare_a_persistence_fact(catalog):
    for family in ("DISABLED_SERVICE_WITH_RESTART_MECHANISM",
                   "SERVICE_STATE_DIFFERS_ACROSS_REBOOT",
                   "SCHEDULED_TASK_RECREATES_COMPONENT"):
        specs = [f for f in catalog if f.family == family]
        for spec in specs:
            assert any(f.decides == "PERSISTENCE" for f in spec.decisive_facts), family


def test_every_setup_op_is_supported_and_reversible(catalog):
    for spec in catalog:
        for op in spec.setup_ops:
            assert op.op in SUPPORTED_SETUP_OPS
        assert spec.cleanup_ops, spec.fixture_id


def test_all_fixture_material_lives_under_the_lab_prefixes(catalog):
    """Cleanup is only exhaustive if nothing escapes the lab namespace."""
    for spec in catalog:
        for op in spec.setup_ops:
            for key in ("path", "dest"):
                value = op.args.get(key)
                if value:
                    assert str(value).startswith(LAB_FILE_ROOT), (spec.fixture_id, value)
            if op.op == "new_arp_entry":
                assert LAB_ARP_PREFIX in op.args["key"]
            if op.op in ("new_service", "new_scheduled_task"):
                name = op.args.get("name") or op.args.get("remove")
                assert str(name).startswith("RV3Lab_")
            if op.op == "new_local_user":
                name = op.args.get("name") or op.args.get("remove")
                assert str(name).startswith("rv3lab_")


def test_no_fixture_installs_anything_actually_vulnerable(catalog):
    """Fixtures are synthetic: a version string and a location, never real code."""
    for spec in catalog:
        for op in spec.setup_ops:
            source = str(op.args.get("source", ""))
            if source:
                assert source == r"C:\Windows\System32\notepad.exe", spec.fixture_id
            blob = " ".join(str(v) for v in op.args.values()).lower()
            for banned in ("http://", "https://", "invoke-", "downloadstring", ".msi", ".msu"):
                assert banned not in blob, (spec.fixture_id, banned)


def test_manifest_is_stable_and_covers_ground_truth():
    first, second = build_fixture_manifest(), build_fixture_manifest()
    assert first["manifest_sha256"] == second["manifest_sha256"]
    assert first["fixture_count"] >= 40
    assert first["provisioning_observations"] is None
    assert "specification only" in first["ground_truth_basis"]


def test_manifest_records_direct_observations_when_provisioned():
    observed = [{"kind": "file", "path": "C:\\RV3Lab\\x.exe", "file_version": "10.0.1"}]
    manifest = build_fixture_manifest(observed)
    assert manifest["provisioning_observations"] == observed
    assert "direct observation" in manifest["ground_truth_basis"]
    assert manifest["manifest_sha256"] != build_fixture_manifest()["manifest_sha256"]


def test_provisioning_plan_covers_every_fixture(catalog):
    plan = provisioning_plan()
    assert plan["operation_count"] == sum(len(f.setup_ops) for f in catalog)
    assert plan["plan_sha256"] == sha256_json(plan["operations"])
    assert "WRITES to the target machine" in plan["warning"]
    assert {op["fixture_id"] for op in plan["operations"]} <= {f.fixture_id for f in catalog}
