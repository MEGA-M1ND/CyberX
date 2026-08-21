"""Metric, interval, and paired-test arithmetic."""
from __future__ import annotations

import math

from rvbench.scorer.scorer import is_false_failure, is_false_safe, paired_comparison, score_arm
from rvbench.scorer.stats import mcnemar, significance_label, wilson_interval

SAFE = "VERIFIED_REMEDIATED"
FAILED = "REMEDIATION_FAILED"


def _rows(pairs, arm="X"):
    return [
        {"case_id": f"c{i}", "arm": arm, "predicted": p, "truth": t,
         "category": "A_GENUINE_SUCCESS", "confidence": 1.0, "reason_codes": [],
         "latency_ms": 1.0, "rationale": "", "evidence": {}}
        for i, (p, t) in enumerate(pairs)
    ]


def test_false_safe_definition():
    assert is_false_safe(SAFE, FAILED)
    assert not is_false_safe(SAFE, SAFE)
    assert not is_false_safe(FAILED, FAILED)
    assert is_false_failure(FAILED, SAFE)
    assert not is_false_failure(SAFE, SAFE)


def test_false_safe_rate_arithmetic():
    m = score_arm("X", _rows([(SAFE, FAILED), (SAFE, FAILED), (SAFE, SAFE), (FAILED, FAILED)]))
    assert m["false_safe_count"] == 2
    assert m["false_safe_rate"] == 0.5
    assert m["accuracy"] == 0.5
    # precision for VERIFIED_REMEDIATED: 1 true positive out of 3 predictions
    assert math.isclose(m["verified_remediated_precision"], 1 / 3)
    assert math.isclose(m["verified_remediated_recall"], 1.0)


def test_wilson_interval_known_values():
    lo, hi = wilson_interval(5, 10)
    assert math.isclose(lo, 0.2365931, abs_tol=1e-6)
    assert math.isclose(hi, 0.7634069, abs_tol=1e-6)
    assert wilson_interval(0, 20)[0] == 0.0
    assert wilson_interval(20, 20)[1] == 1.0
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_wilson_interval_brackets_the_point_estimate():
    for k in range(0, 49):
        lo, hi = wilson_interval(k, 48)
        assert lo <= k / 48 <= hi


def test_mcnemar_exact_matches_hand_computation():
    # b=5, c=0, n=5 -> two-sided exact p = 2 * 0.5**5
    r = mcnemar(5, 0)
    assert math.isclose(r["p_exact"], 2 * 0.5 ** 5)
    assert r["n_discordant"] == 5


def test_mcnemar_symmetric_and_bounded():
    assert mcnemar(3, 3)["p_exact"] == 1.0
    assert mcnemar(7, 2)["p_exact"] == mcnemar(2, 7)["p_exact"]
    assert mcnemar(0, 0)["p_exact"] == 1.0


def test_mcnemar_chi2_continuity_correction():
    r = mcnemar(10, 0)
    assert math.isclose(r["chi2"], (abs(10 - 0) - 1) ** 2 / 10)


def test_significance_labels_are_conservative():
    assert significance_label(0.5, 10) == "inconclusive"
    assert significance_label(0.001, 20) == "statistically significant"
    assert significance_label(0.03, 5).startswith("directional")
    assert significance_label(0.0, 0) == "inconclusive"


def test_paired_comparison_counts_discordant_pairs():
    a = _rows([(SAFE, FAILED), (FAILED, FAILED), (SAFE, FAILED)], "A")
    b = _rows([(FAILED, FAILED), (FAILED, FAILED), (SAFE, FAILED)], "B")
    cmp = paired_comparison("A", a, "B", b, metric="false_safe")
    assert cmp["b"] == 1 and cmp["c"] == 0
    assert cmp["errors_unique_to_A"] == ["c0"]


def test_detection_rates_are_none_when_unsupported():
    m = score_arm("X", _rows([(SAFE, SAFE)]))
    assert m["regression_detection_rate"] is None
