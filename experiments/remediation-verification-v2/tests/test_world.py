"""Latent world: determinism, timeline semantics, predicate correctness."""
from __future__ import annotations

import pytest

from rv2.world.predicates import LatentPredicateError, evaluate, top_level_components
from rv2.world.scenarios import FAMILIES, build_world
from rv2.world.state import (
    DeviceState,
    InstalledPackage,
    filesystem_root_of,
    project_reboot,
    registry_root_of,
    version_below,
)


def test_version_comparison():
    assert version_below("1.4.2", "1.4.5")
    assert not version_below("1.4.5", "1.4.5")
    assert not version_below("1.10.0", "1.4.5")
    assert version_below("1.4", "1.4.5")


def test_root_resolution_prefers_the_longest_match():
    assert registry_root_of("HKLM\\SOFTWARE\\WOW6432Node\\X") == "HKLM\\SOFTWARE\\WOW6432Node"
    assert registry_root_of("HKLM\\SOFTWARE\\Policies\\X") == "HKLM\\SOFTWARE"
    assert filesystem_root_of("C:\\Program Files (x86)\\A\\b.exe") == "C:\\Program Files (x86)"
    assert filesystem_root_of("C:\\Program Files\\A\\b.exe") == "C:\\Program Files"


def test_world_generation_is_deterministic():
    for family in FAMILIES:
        a = build_world(family, 7, "case")
        b = build_world(family, 7, "case")
        assert [d.to_dict() for d in a.devices] == [d.to_dict() for d in b.devices]


def test_different_seeds_vary_the_world():
    variants = {build_world("GENUINE_REMEDIATION", s, "c").devices[0].current.fingerprint()
                for s in range(12)}
    assert len(variants) > 1


def test_every_family_has_a_baseline_and_a_post_remediation_snapshot():
    for family in FAMILIES:
        world = build_world(family, 3, "c")
        for device in world.devices:
            labels = [s.label for s in device.timeline]
            assert labels[0] == "baseline"
            assert "post_remediation" in labels


def test_side_by_side_keeps_both_install_scopes():
    world = build_world("SIDE_BY_SIDE_VULNERABLE", 1, "c")
    scopes = {p.install_scope for p in world.devices[0].current.packages}
    assert scopes == {"machine", "per_user"}


def test_inventory_can_move_without_the_binary():
    world = build_world("INVENTORY_UPDATED_BINARY_UNCHANGED", 1, "c")
    state = world.devices[0].current
    baseline = world.devices[0].snapshot("baseline").state
    assert state.packages[0].version != baseline.packages[0].version
    assert state.files == baseline.files


def test_automatic_service_returns_after_restart():
    state = DeviceState(services={"s": {"status": "stopped", "startup_type": "automatic"}})
    assert project_reboot(state).services["s"]["status"] == "running"


def test_disabled_service_stays_down_after_restart():
    state = DeviceState(services={"s": {"status": "running", "startup_type": "disabled"}})
    assert project_reboot(state).services["s"]["status"] == "stopped"


def test_staged_patch_lands_after_restart():
    state = DeviceState(patches={"KB1": {"installed": False, "staged": True}}, reboot_pending=True)
    after = project_reboot(state)
    assert after.patches["KB1"] == {"installed": True, "staged": False}
    assert after.reboot_pending is False


def test_package_predicate_sees_every_installed_version():
    state = DeviceState(packages=[InstalledPackage("p", "1.0.0"), InstalledPackage("p", "2.0.0")])
    assert evaluate({"op": "package_version_below", "package": "p", "fixed_version": "2.0.0"}, state)


def test_missing_registry_key_is_not_secure():
    node = {"op": "registry_not_equals", "path": "HKLM\\X", "value": 0}
    assert evaluate(node, DeviceState())
    assert not evaluate(node, DeviceState(registry={"HKLM\\X": 0}))


def test_composite_components_are_separable():
    node = {"op": "any_of", "operands": [{"id": "a", "op": "patch_missing", "kb": "K"},
                                         {"id": "b", "op": "file_present", "path": "x"}]}
    assert len(top_level_components(node)) == 2
    assert len(top_level_components({"op": "file_present", "path": "x"})) == 1


def test_unknown_latent_op_is_rejected():
    with pytest.raises(LatentPredicateError):
        evaluate({"op": "rm_rf"}, DeviceState())
