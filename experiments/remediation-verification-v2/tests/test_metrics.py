"""Metric arithmetic, denominators, intervals, and paired tests."""
from __future__ import annotations

import math

import pytest

from rv2.metrics.metrics import (
    METRIC_DEFINITIONS,
    abstention,
    active_recovery,
    confusion_matrix,
    false_assurance,
    harm_detection_recall,
    harm_not_blessed,
    metric_block,
    paired_comparison,
    partial_recall,
    unsafe_escape,
    verified_precision,
    verified_recall,
)
from rv2.metrics.stats import cluster_bootstrap, mcnemar, significance_label, wilson_interval

V = "VERIFIED_REMEDIATED"
F = "REMEDIATION_FAILED"
P = "PARTIALLY_REMEDIATED"
R = "REGRESSION_INTRODUCED"
N = "NEW_SECURITY_RISK"
I = "INSUFFICIENT_EVIDENCE"


def rows(pairs, family="FAM", arm="X"):
    return [{"condition_id": f"c{i}", "arm": arm, "verdict": v, "truth": t, "family": family,
             "coverage": 0.8, "mechanism": "RANDOM_MISSING", "evidence_requests": [],
             "latency_units": 1.0, "reason_codes": []}
            for i, (v, t) in enumerate(pairs)]


# ------------------------------------------------------------------ denominators
def test_false_assurance_denominator_is_claims_not_cases():
    data = rows([(V, F), (V, V), (F, F), (I, F)])
    assert false_assurance(data) == 0.5           # 1 wrong of 2 claims
    assert unsafe_escape(data) == pytest.approx(1 / 3)  # 1 escape of 3 unsafe cases
    assert abstention(data) == 0.25


def test_false_assurance_is_undefined_with_no_claims():
    assert false_assurance(rows([(I, F), (F, F)])) is None
    assert verified_precision(rows([(I, F)])) is None


def test_precision_and_false_assurance_are_complements():
    data = rows([(V, F), (V, V), (V, V), (F, F)])
    assert false_assurance(data) + verified_precision(data) == pytest.approx(1.0)


def test_recall_denominator_is_actually_remediated_cases():
    data = rows([(V, V), (I, V), (V, F)])
    assert verified_recall(data) == 0.5


def test_unsafe_set_excludes_regression_but_includes_new_risk():
    assert unsafe_escape(rows([(V, R)])) is None      # no unsafe cases at all
    assert unsafe_escape(rows([(V, N)])) == 1.0
    assert unsafe_escape(rows([(V, P)])) == 1.0


def test_harm_metrics_separate_exact_label_from_never_blessing():
    data = rows([(I, R), (V, N)])
    assert harm_detection_recall(data) == 0.0
    assert harm_not_blessed(data) == 0.5


def test_partial_recall_needs_the_exact_label():
    assert partial_recall(rows([(P, P), (F, P)])) == 0.5


def test_every_metric_has_a_written_denominator():
    for name in ("false_assurance_rate", "unsafe_escape_rate", "verified_precision",
                 "verified_recall", "abstention_rate", "harm_detection_recall",
                 "harm_not_blessed_rate", "partial_remediation_recall"):
        assert METRIC_DEFINITIONS[name]["numerator"]
        assert METRIC_DEFINITIONS[name]["denominator"]


def test_metric_block_reports_counts_alongside_rates():
    block = metric_block(rows([(V, F), (V, V), (I, P)]), with_intervals=False)
    assert block["false_assurance_rate"]["numerator"] == 1
    assert block["false_assurance_rate"]["denominator"] == 2
    assert block["n"] == 3


def test_confusion_matrix_totals_match_the_row_count():
    data = rows([(V, F), (I, P), (R, R)])
    matrix = confusion_matrix(data)
    assert sum(v for row in matrix.values() for v in row.values()) == 3


# ------------------------------------------------------------------ intervals
def test_wilson_known_values():
    lo, hi = wilson_interval(5, 10)
    assert math.isclose(lo, 0.2365931, abs_tol=1e-6)
    assert math.isclose(hi, 0.7634069, abs_tol=1e-6)


def test_wilson_brackets_the_point_estimate_everywhere():
    for k in range(0, 51):
        lo, hi = wilson_interval(k, 50)
        assert lo <= k / 50 <= hi


def test_cluster_bootstrap_is_deterministic_and_wider_than_wilson():
    clusters = {f"fam{i}": rows([(V, F), (V, V)], family=f"fam{i}") for i in range(8)}
    first = cluster_bootstrap(clusters, false_assurance, draws=400)
    second = cluster_bootstrap(clusters, false_assurance, draws=400)
    assert first == second
    assert first["point"] == 0.5


def test_cluster_bootstrap_reports_undefined_when_the_statistic_rarely_exists():
    clusters = {f"fam{i}": rows([(I, F)], family=f"fam{i}") for i in range(6)}
    result = cluster_bootstrap(clusters, false_assurance, draws=200)
    assert result["lo"] is None
    assert result["defined_draws"] == 0


# ------------------------------------------------------------------ paired tests
def test_mcnemar_matches_hand_computation():
    result = mcnemar(5, 0)
    assert math.isclose(result["p_exact"], 2 * 0.5 ** 5)
    assert result["n_discordant"] == 5
    assert result["risk_difference"] == 1.0


def test_mcnemar_is_symmetric_and_bounded():
    assert mcnemar(3, 3)["p_exact"] == 1.0
    assert mcnemar(7, 2)["p_exact"] == mcnemar(2, 7)["p_exact"]
    assert mcnemar(0, 0)["p_exact"] == 1.0
    assert mcnemar(4, 2)["odds_ratio"] == 2.0


def test_significance_labels_are_conservative():
    assert significance_label(0.5, 20) == "inconclusive"
    assert significance_label(0.001, 40) == "statistically significant"
    assert significance_label(0.03, 6).startswith("directional")
    assert significance_label(0.0, 0) == "inconclusive"


def test_paired_comparison_counts_discordant_pairs():
    a = rows([(V, F), (F, F)], arm="A")
    b = rows([(F, F), (F, F)], arm="B")
    result = paired_comparison("A", a, "B", b, "false_assurance")
    assert result["b"] == 1 and result["c"] == 0
    assert result["errors_only_in_first"] == ["c0"]


def test_paired_comparison_supports_all_three_error_definitions():
    a = rows([(V, R)], arm="A")
    b = rows([(I, R)], arm="B")
    assert paired_comparison("A", a, "B", b, "false_assurance")["b"] == 1
    assert paired_comparison("A", a, "B", b, "unsafe_escape")["b"] == 0  # regression is not unsafe
    assert paired_comparison("A", a, "B", b, "wrong_verdict")["b"] == 0  # both wrong


def test_active_recovery_only_counts_reference_abstentions():
    reference = rows([(I, F), (I, F), (F, F)], arm="D")
    active = rows([(F, F), (I, F), (F, F)], arm="E")
    result = active_recovery(reference, active)
    assert result["reference_abstentions"] == 2
    assert result["recovered_correct"] == 1
    assert result["recovery_rate"] == 0.5
    assert result["new_false_assurances_created"] == 0


def test_active_recovery_flags_new_false_assurance():
    reference = rows([(I, F)], arm="D")
    active = rows([(V, F)], arm="E")
    assert active_recovery(reference, active)["new_false_assurances_created"] == 1
