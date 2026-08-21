"""Collectors must not be able to reach fixture ground truth."""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest
from _srcutil import code_only

import rv3.collectors.importers as importers
import rv3.collectors.real as real
import rv3.contracts.catalog as contract_catalog
import rv3.contracts.scope as scope

COLLECTOR_MODULES = [real, importers, scope, contract_catalog]
FORBIDDEN_TOKENS = ["build_catalog", "FixtureSpec", "expected_vulnerable", "expected_regression",
                    "expected_persistent_after_reboot", "fixture_hash", "family",
                    "build_fixture_manifest", "decisive_facts"]
PS_DIR = Path(__file__).resolve().parents[1] / "powershell"


def _imports(module):
    tree = ast.parse(inspect.getsource(module))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = "." * node.level + (node.module or "")
            names.append(base)
            names.extend(f"{base}.{alias.name}" for alias in node.names)
    return names


@pytest.mark.parametrize("module", [real, importers], ids=lambda m: m.__name__)
def test_collector_modules_do_not_import_the_fixture_catalog(module):
    for name in _imports(module):
        assert "fixtures.catalog" not in name, f"{module.__name__} imports {name}"
        assert "analysis" not in name, f"{module.__name__} imports {name}"


def test_the_scope_contract_sees_only_a_facts_coordinates():
    """A contract decides coverage from coordinates, never from expectations."""
    source = code_only(inspect.getsource(scope.CollectorContract.covers))
    for token in ("expected_vulnerable", "expected_regression", "family", "fixture_id"):
        assert token not in source


@pytest.mark.parametrize("module", COLLECTOR_MODULES, ids=lambda m: m.__name__)
def test_collector_side_code_never_names_ground_truth(module):
    code = code_only(inspect.getsource(module))
    for token in FORBIDDEN_TOKENS:
        assert token not in code, f"{module.__name__} references {token} in executable code"


def test_collector_view_exposes_no_expectations(catalog):
    """The only fixture data a collector receives."""
    for spec in catalog:
        view = spec.collector_view()
        blob = json.dumps(view)
        assert spec.family not in blob
        for banned in ("expected", "vulnerable", "regression", "decisive", "persistent"):
            assert banned not in blob.lower(), (spec.fixture_id, banned)
        assert set(view) == {"fixture_id", "file_root", "registry_root", "arp_prefix",
                             "service_prefix", "task_prefix"}


def test_collector_view_targets_are_not_the_decisive_coordinates(catalog):
    """Pointing a collector at a fixture must not hand it the answer."""
    for spec in catalog:
        view = spec.collector_view()
        for fact in spec.decisive_facts:
            assert fact.locator not in view.values()


def _ps_code_only(text: str) -> str:
    import re
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_powershell_scripts_carry_no_fixture_truth(catalog):
    """No family name, no expectation, and no decisive locator in any collector.

    Prose may describe the mechanism - a script explaining that it re-queries
    when "a decisive fact is unresolved" is documentation, not ground truth. What
    must never appear is the answer: which fixture, which expectation, or which
    exact location the decisive evidence sits at.
    """
    from rv3.vocab import FAMILIES
    locators = {f.locator for spec in catalog for f in spec.decisive_facts}
    fixture_ids = {spec.fixture_id for spec in catalog}
    for script in sorted(PS_DIR.glob("Collect-*.ps1")):
        text = script.read_text()
        code = _ps_code_only(text)
        for family in FAMILIES:
            assert family not in text, f"{script.name} names family {family}"
        for token in ("expected_vulnerable", "expected_regression",
                      "expected_persistent_after_reboot", "fixture_hash"):
            assert token not in text, f"{script.name} names {token}"
        for locator in locators:
            assert locator not in code, f"{script.name} hard-codes decisive locator {locator}"
        for fixture_id in fixture_ids:
            assert fixture_id not in code, f"{script.name} hard-codes fixture {fixture_id}"


def test_observations_artifact_carries_no_labels(root):
    path = root / "artifacts" / "raw-observations.json"
    if not path.exists():
        pytest.skip("run `python3 run_experiment.py` first")
    blob = path.read_text()
    for token in ("expected_vulnerable", "expected_regression", "MACHINE_WIDE_64BIT"):
        assert token not in blob


def test_classification_needs_both_a_contract_and_a_fact(classifications):
    """Every classification is a function of contract and coordinates only."""
    for row in classifications:
        assert row.gap_class
        assert row.coordinates is not None
        assert isinstance(row.completeness_claimed, bool)
