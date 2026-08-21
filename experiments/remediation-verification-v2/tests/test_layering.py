"""Leakage guards.

These fail if a future edit hands a verifier the answer key, directly or by
importing something that knows it.
"""
from __future__ import annotations

import ast
import inspect

import pytest
from _srcutil import code_only

import rv2.verifiers.arm_a_status_only as arm_a
import rv2.verifiers.arm_b_target_state as arm_b
import rv2.verifiers.arm_c_scope_unaware as arm_c
import rv2.verifiers.arm_d_scope_aware as arm_d
import rv2.verifiers.arm_e_active as arm_e
import rv2.verifiers.base as arm_base

VERIFIER_MODULES = [arm_base, arm_a, arm_b, arm_c, arm_d, arm_e]

FORBIDDEN_PACKAGES = {"rv2.world", "rv2.oracle", "rv2.collect", "rv2.bench", "rv2.metrics",
                      "world", "oracle", "collect", "bench", "metrics"}
FORBIDDEN_TOKENS = ["derive_truth", "TruthLabel", "LatentWorld", "LatentDevice", "DeviceState",
                    "EvidenceService", "ConditionPlan", "decisive_hint", "truth", "ground_truth",
                    "_true_state", "score_everything"]


def _imports(module):
    tree = ast.parse(inspect.getsource(module))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            level_prefix = "." * node.level
            found.append(level_prefix + base)
            found.extend(f"{level_prefix}{base}.{alias.name}" for alias in node.names)
    return found


@pytest.mark.parametrize("module", VERIFIER_MODULES, ids=lambda m: m.__name__)
def test_verifier_modules_import_only_the_observation_layer(module):
    for name in _imports(module):
        normalised = name.lstrip(".")
        head = normalised.split(".")[0]
        assert head not in FORBIDDEN_PACKAGES, f"{module.__name__} imports {name}"
        assert "world" not in normalised.split("."), f"{module.__name__} imports {name}"
        assert "oracle" not in normalised.split("."), f"{module.__name__} imports {name}"


@pytest.mark.parametrize("module", VERIFIER_MODULES, ids=lambda m: m.__name__)
def test_verifier_code_never_names_ground_truth(module):
    code = code_only(inspect.getsource(module))
    for token in FORBIDDEN_TOKENS:
        assert token not in code, f"{module.__name__} references {token} in executable code"


def test_oracle_and_verifiers_share_no_predicate_evaluator():
    import rv2.obs.observed_predicates as observed
    import rv2.world.predicates as latent
    assert latent.__file__ != observed.__file__
    latent_src = code_only(inspect.getsource(latent))
    assert "observed_predicates" not in latent_src
    observed_src = code_only(inspect.getsource(observed))
    assert "world" not in observed_src.split()


def test_oracle_and_arm_d_share_no_verdict_helper():
    import rv2.oracle.truth as oracle
    oracle_code = code_only(inspect.getsource(oracle))
    arm_d_code = code_only(inspect.getsource(arm_d))
    assert "analyse" not in oracle_code
    assert "derive_truth" not in arm_d_code
    for name in _imports(arm_d):
        assert "oracle" not in name
    for name in _imports(oracle):
        assert "verifiers" not in name


def test_observation_package_carries_no_truth_fields():
    from rv2.obs.package import ObservationPackage
    fields = set(ObservationPackage.__dataclass_fields__)
    for banned in ("truth", "label", "family", "category", "expected", "decisive_hint",
                   "coverage", "mechanism"):
        assert banned not in fields


def test_serialised_packages_contain_no_truth_or_family_labels(root):
    """The strongest check: the bytes the arms actually saw."""
    import gzip
    import json

    from rv2.vocab import ALL_TRUTH_LABELS
    from rv2.world.scenarios import FAMILIES

    path = root / "cases" / "holdout-observations.jsonl.gz"
    if not path.exists():
        pytest.skip("run `python3 run_experiment.py` first")
    with gzip.open(path, "rt") as fh:
        for line in fh:
            entry = json.loads(line)
            blob = json.dumps(entry["package"])
            for family in FAMILIES:
                assert family not in blob
            for label in ALL_TRUTH_LABELS:
                assert label not in blob
            assert "decisive_hint" not in blob
            assert "UNDECLARED_GAP" not in blob


def test_run_predictions_never_calls_the_oracle():
    from rv2.bench import run
    src = code_only(inspect.getsource(run.run_predictions))
    assert "derive_truth" not in src
    assert "truth" not in src


def test_predictions_are_frozen_before_truth_is_read():
    from rv2.bench import run
    src = inspect.getsource(run.run_partition)
    assert src.index("frozen_path.open") < src.index("derive_truth")


def test_verifier_source_tree_has_no_path_to_the_world(root):
    """Belt and braces: grep the files, not just the imported modules."""
    for path in (root / "src" / "rv2" / "verifiers").rglob("*.py"):
        code = code_only(path.read_text())
        assert "rv2.world" not in code
        assert "rv2.oracle" not in code
        assert "..world" not in code
        assert "..oracle" not in code
