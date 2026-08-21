"""Experiment-integrity guards.

These tests exist so that a future edit cannot quietly hand the verifier the
answer key.
"""
from __future__ import annotations

import ast
import inspect
import json

from _srcutil import code_only

import rvbench.verifiers.independent as independent
import rvbench.verifiers.status_only as status_only
import rvbench.verifiers.target_state as target_state
from rvbench.cases import PublicCase

FORBIDDEN_TOKENS = [
    "ground_truth", "GroundTruth", "expected_verifier_answer",
    "labels.json", "scenarios.json", "scorer",
]


def test_public_case_file_has_no_ground_truth_fields(root):
    raw = json.loads((root / "cases" / "public" / "cases.json").read_text())
    allowed = {"case_id", "title", "os", "fleet_size", "vulnerability_predicate",
               "remediation_intent", "required_health_checks", "notes"}
    for case in raw["cases"]:
        assert set(case) <= allowed, set(case) - allowed
        blob = json.dumps(case).lower()
        for token in ("ground_truth", "label", "expected_verdict", "outcome", "category"):
            assert token not in blob, f"{case['case_id']} leaks {token}"


def test_public_cases_do_not_mention_verdicts(root):
    blob = (root / "cases" / "public" / "cases.json").read_text()
    for verdict in ("VERIFIED_REMEDIATED", "REMEDIATION_FAILED", "PARTIALLY_REMEDIATED",
                    "REGRESSION_INTRODUCED", "NEW_SECURITY_RISK", "INSUFFICIENT_EVIDENCE"):
        assert verdict not in blob


def _code_only(src: str) -> str:
    """Source with docstrings, string literals, and comments removed.

    Prose is allowed to mention the scorer; executable code is not.
    """
    import io
    import tokenize
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in (tokenize.STRING, tokenize.COMMENT):
            continue
        out.append(tok.string)
    return " ".join(out)


def test_verifier_modules_import_nothing_from_the_scorer():
    for module in (status_only, target_state, independent):
        src = inspect.getsource(module)
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                name = getattr(node, "module", "") or ""
                names = name + " " + " ".join(a.name for a in node.names)
                assert "scorer" not in names, f"{module.__name__} imports {names}"
                assert "ground_truth" not in names, f"{module.__name__} imports {names}"
        code = code_only(src)
        for token in FORBIDDEN_TOKENS:
            assert token not in code, f"{module.__name__} references {token} in executable code"


def test_verifier_input_carries_only_public_case_and_adapter():
    from rvbench.verifiers.base import VerifierInput
    fields = set(VerifierInput.__dataclass_fields__)
    assert fields == {"case", "adapter"}


def test_public_case_dataclass_has_no_label_field():
    assert not any("label" in f or "truth" in f for f in PublicCase.__dataclass_fields__)


def test_run_predictions_never_touches_ground_truth():
    from rvbench import runner
    src = inspect.getsource(runner.run_predictions)
    assert "ground_truth" not in src
    assert "labels.json" not in src


def test_predictions_are_frozen_before_scoring():
    """`run()` must write raw_results.jsonl before load_ground_truth is called."""
    from rvbench import runner
    src = inspect.getsource(runner.run)
    assert src.index("raw_results.jsonl") < src.index("load_ground_truth")
