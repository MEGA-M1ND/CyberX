"""Ground truth: expected label per family, and precedence behaviour.

These expectations are hand-reasoned from each family's construction.  They
confirm the oracle agrees with the author's intent, which is a real check and a
shallow one - see reports/shared-design-threats.md.
"""
from __future__ import annotations

from rv2.oracle.truth import derive_truth
from rv2.vocab import ALL_TRUTH_LABELS, TruthLabel
from rv2.world.scenarios import FAMILIES, build_world

EXPECTED = {
    "GENUINE_REMEDIATION": TruthLabel.VERIFIED_REMEDIATED,
    "EXIT_ZERO_NO_CHANGE": TruthLabel.REMEDIATION_FAILED,
    "WRONG_REGISTRY_KEY": TruthLabel.REMEDIATION_FAILED,
    "WRONG_PRODUCT_IDENTITY": TruthLabel.REMEDIATION_FAILED,
    "SIDE_BY_SIDE_VULNERABLE": TruthLabel.REMEDIATION_FAILED,
    "PARTIAL_MULTI_PREDICATE": TruthLabel.PARTIALLY_REMEDIATED,
    "SERVICE_RETURNS_AFTER_REBOOT": TruthLabel.REMEDIATION_FAILED,
    "REBOOT_REQUIRED_NOT_PERFORMED": TruthLabel.PARTIALLY_REMEDIATED,
    "VULNERABLE_BINARY_ON_DISK": TruthLabel.REMEDIATION_FAILED,
    "INVENTORY_UPDATED_BINARY_UNCHANGED": TruthLabel.REMEDIATION_FAILED,
    "GROUP_PARTIAL_ROLLOUT": TruthLabel.PARTIALLY_REMEDIATED,
    "REGRESSION_INTRODUCED": TruthLabel.REGRESSION_INTRODUCED,
    "NEW_EXPOSURE_INTRODUCED": TruthLabel.NEW_SECURITY_RISK,
}


def test_every_family_has_an_expectation():
    assert set(EXPECTED) == set(FAMILIES)


def test_oracle_matches_expectations_across_seeds():
    for family, expected in EXPECTED.items():
        for seed in (1, 17, 99, 512):
            truth = derive_truth(build_world(family, seed, "c"))
            assert truth.label == expected.value, f"{family} seed={seed} -> {truth.label}"


def test_oracle_never_abstains():
    assert "INSUFFICIENT_EVIDENCE" not in ALL_TRUTH_LABELS
    for family in FAMILIES:
        assert derive_truth(build_world(family, 5, "c")).label in ALL_TRUTH_LABELS


def test_oracle_counts_devices_no_collector_could_reach():
    world = build_world("GROUP_PARTIAL_ROLLOUT", 4, "c")
    assert any(not d.enumerable for d in world.devices)
    assert derive_truth(world).label == TruthLabel.PARTIALLY_REMEDIATED.value


def test_security_outranks_functionality():
    """A still-vulnerable device is a failure even if a health check also broke."""
    world = build_world("EXIT_ZERO_NO_CHANGE", 2, "c")
    world.devices[0].current.application_health[world.required_health_checks[0]] = False
    assert derive_truth(world).label == TruthLabel.REMEDIATION_FAILED.value


def test_new_exposure_outranks_regression():
    world = build_world("REGRESSION_INTRODUCED", 2, "c")
    world.devices[0].current.security_posture["host_firewall_disabled"] = True
    assert derive_truth(world).label == TruthLabel.NEW_SECURITY_RISK.value


def test_staged_and_non_persistent_are_told_apart():
    staged = derive_truth(build_world("REBOOT_REQUIRED_NOT_PERFORMED", 8, "c"))
    transient = derive_truth(build_world("SERVICE_RETURNS_AFTER_REBOOT", 8, "c"))
    assert staged.label == TruthLabel.PARTIALLY_REMEDIATED.value
    assert transient.label == TruthLabel.REMEDIATION_FAILED.value
    assert staged.label != transient.label


def test_rationale_is_populated():
    for family in FAMILIES:
        assert derive_truth(build_world(family, 6, "c")).rationale
