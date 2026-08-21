"""Metrics, with every denominator written down.

The v1 report used "false-safe rate" with an all-cases denominator, which
conflates two different questions.  v2 separates them:

    False Assurance Rate  = wrong VERIFIED_REMEDIATED / all VERIFIED_REMEDIATED
                            "when the system says verified, how often is it wrong?"

    Unsafe Escape Rate    = unsafe cases called VERIFIED / all unsafe cases
                            "of the endpoints that are still exposed, what share
                             get waved through?"

An arm that abstains on everything scores perfectly on the second and has no
defined value for the first.  That is why abstention rate and verified-remediation
recall are reported alongside, and why no single number is the headline.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Dict, List, Optional

from ..vocab import (
    ALL_TRUTH_LABELS,
    ALL_VERDICTS,
    ARMS,
    HARM_LABELS,
    REMEDIATED_LABELS,
    UNSAFE_LABELS,
    TruthLabel,
    Verdict,
)
from .stats import cluster_bootstrap, mcnemar, significance_label, wilson_interval

VERIFIED = Verdict.VERIFIED_REMEDIATED.value
ABSTAIN = Verdict.INSUFFICIENT_EVIDENCE.value

# The five degradation mechanisms named in the v2 brief.  UNDECLARED_GAP is a
# sixth, added by this experiment, and is reported separately throughout.
ADVERSARIAL_DECLARED = frozenset({
    "DECISIVE_FIELD_MISSING", "REGRESSION_EVIDENCE_MISSING", "STALE_EVIDENCE",
    "CONTRADICTORY_EVIDENCE", "SCOPE_MISMATCH",
})


# --------------------------------------------------------------------------- #
# Rate primitives.  Each returns None when its denominator is empty, which is
# information rather than a zero.
# --------------------------------------------------------------------------- #
def _rate(numerator: int, denominator: int) -> Optional[float]:
    return (numerator / denominator) if denominator else None


def false_assurance(rows: List[dict]) -> Optional[float]:
    claimed = [r for r in rows if r["verdict"] == VERIFIED]
    wrong = [r for r in claimed if r["truth"] != TruthLabel.VERIFIED_REMEDIATED.value]
    return _rate(len(wrong), len(claimed))


def unsafe_escape(rows: List[dict]) -> Optional[float]:
    unsafe = [r for r in rows if r["truth"] in UNSAFE_LABELS]
    escaped = [r for r in unsafe if r["verdict"] == VERIFIED]
    return _rate(len(escaped), len(unsafe))


def verified_precision(rows: List[dict]) -> Optional[float]:
    claimed = [r for r in rows if r["verdict"] == VERIFIED]
    correct = [r for r in claimed if r["truth"] == TruthLabel.VERIFIED_REMEDIATED.value]
    return _rate(len(correct), len(claimed))


def verified_recall(rows: List[dict]) -> Optional[float]:
    actual = [r for r in rows if r["truth"] in REMEDIATED_LABELS]
    found = [r for r in actual if r["verdict"] == VERIFIED]
    return _rate(len(found), len(actual))


def abstention(rows: List[dict]) -> Optional[float]:
    return _rate(sum(1 for r in rows if r["verdict"] == ABSTAIN), len(rows))


def harm_detection_recall(rows: List[dict]) -> Optional[float]:
    harm = [r for r in rows if r["truth"] in HARM_LABELS]
    caught = [r for r in harm if r["verdict"] == r["truth"]]
    return _rate(len(caught), len(harm))


def harm_not_blessed(rows: List[dict]) -> Optional[float]:
    """Harm cases the arm declined to call remediated.

    Harm-detection recall demands the exact label, which scores "I said verified"
    and "I said I could not tell" identically.  Operationally those are very
    different, so this reports the weaker but more decision-relevant property:
    the harm was at least not waved through.
    """
    harm = [r for r in rows if r["truth"] in HARM_LABELS]
    return _rate(sum(1 for r in harm if r["verdict"] != VERIFIED), len(harm))


def partial_recall(rows: List[dict]) -> Optional[float]:
    partial = [r for r in rows if r["truth"] == TruthLabel.PARTIALLY_REMEDIATED.value]
    caught = [r for r in partial if r["verdict"] == TruthLabel.PARTIALLY_REMEDIATED.value]
    return _rate(len(caught), len(partial))


def accuracy(rows: List[dict]) -> Optional[float]:
    return _rate(sum(1 for r in rows if r["verdict"] == r["truth"]), len(rows))


def requests_per_case(rows: List[dict]) -> float:
    return sum(len(r.get("evidence_requests", [])) for r in rows) / len(rows) if rows else 0.0


def request_success_rate(rows: List[dict]) -> Optional[float]:
    made = [q for r in rows for q in r.get("evidence_requests", [])]
    return _rate(sum(1 for q in made if q.get("granted")), len(made))


def decision_relevant_rate(rows: List[dict]) -> Optional[float]:
    made = [q for r in rows for q in r.get("evidence_requests", [])]
    return _rate(sum(1 for q in made if q.get("decision_relevant")), len(made))


METRIC_DEFINITIONS: Dict[str, Dict[str, str]] = {
    "false_assurance_rate": {
        "numerator": "predictions of VERIFIED_REMEDIATED whose truth is not VERIFIED_REMEDIATED",
        "denominator": "all predictions of VERIFIED_REMEDIATED"},
    "unsafe_escape_rate": {
        "numerator": "cases whose truth is UNSAFE (REMEDIATION_FAILED, PARTIALLY_REMEDIATED, "
                     "NEW_SECURITY_RISK) predicted VERIFIED_REMEDIATED",
        "denominator": "all cases whose truth is UNSAFE"},
    "verified_precision": {
        "numerator": "correct predictions of VERIFIED_REMEDIATED",
        "denominator": "all predictions of VERIFIED_REMEDIATED"},
    "verified_recall": {
        "numerator": "correct predictions of VERIFIED_REMEDIATED",
        "denominator": "all cases whose truth is VERIFIED_REMEDIATED"},
    "abstention_rate": {
        "numerator": "predictions of INSUFFICIENT_EVIDENCE",
        "denominator": "all cases"},
    "harm_detection_recall": {
        "numerator": "cases whose truth is REGRESSION_INTRODUCED or NEW_SECURITY_RISK predicted "
                     "with that exact label",
        "denominator": "all cases whose truth is REGRESSION_INTRODUCED or NEW_SECURITY_RISK"},
    "harm_not_blessed_rate": {
        "numerator": "harm cases NOT predicted VERIFIED_REMEDIATED (any other verdict, including "
                     "INSUFFICIENT_EVIDENCE)",
        "denominator": "all cases whose truth is REGRESSION_INTRODUCED or NEW_SECURITY_RISK"},
    "partial_remediation_recall": {
        "numerator": "cases whose truth is PARTIALLY_REMEDIATED predicted PARTIALLY_REMEDIATED",
        "denominator": "all cases whose truth is PARTIALLY_REMEDIATED"},
    "accuracy": {"numerator": "predictions equal to truth", "denominator": "all cases"},
    "evidence_requests_per_case": {
        "numerator": "additional evidence requests made", "denominator": "all cases"},
    "request_success_rate": {
        "numerator": "granted requests", "denominator": "all requests made"},
    "decision_relevant_request_rate": {
        "numerator": "requests naming evidence that was blocking the verdict when asked",
        "denominator": "all requests made"},
}

RATE_FUNCTIONS: Dict[str, Callable[[List[dict]], Optional[float]]] = {
    "false_assurance_rate": false_assurance,
    "unsafe_escape_rate": unsafe_escape,
    "verified_precision": verified_precision,
    "verified_recall": verified_recall,
    "abstention_rate": abstention,
    "harm_detection_recall": harm_detection_recall,
    "harm_not_blessed_rate": harm_not_blessed,
    "partial_remediation_recall": partial_recall,
    "accuracy": accuracy,
}

_DENOMINATORS: Dict[str, Callable[[List[dict]], List[dict]]] = {
    "false_assurance_rate": lambda rows: [r for r in rows if r["verdict"] == VERIFIED],
    "unsafe_escape_rate": lambda rows: [r for r in rows if r["truth"] in UNSAFE_LABELS],
    "verified_precision": lambda rows: [r for r in rows if r["verdict"] == VERIFIED],
    "verified_recall": lambda rows: [r for r in rows if r["truth"] in REMEDIATED_LABELS],
    "abstention_rate": lambda rows: list(rows),
    "harm_detection_recall": lambda rows: [r for r in rows if r["truth"] in HARM_LABELS],
    "harm_not_blessed_rate": lambda rows: [r for r in rows if r["truth"] in HARM_LABELS],
    "partial_remediation_recall": lambda rows: [
        r for r in rows if r["truth"] == TruthLabel.PARTIALLY_REMEDIATED.value],
    "accuracy": lambda rows: list(rows),
}

_NUMERATORS: Dict[str, Callable[[List[dict]], List[dict]]] = {
    "false_assurance_rate": lambda rows: [
        r for r in rows if r["verdict"] == VERIFIED and r["truth"] != VERIFIED],
    "unsafe_escape_rate": lambda rows: [
        r for r in rows if r["truth"] in UNSAFE_LABELS and r["verdict"] == VERIFIED],
    "verified_precision": lambda rows: [
        r for r in rows if r["verdict"] == VERIFIED and r["truth"] == VERIFIED],
    "verified_recall": lambda rows: [
        r for r in rows if r["truth"] in REMEDIATED_LABELS and r["verdict"] == VERIFIED],
    "abstention_rate": lambda rows: [r for r in rows if r["verdict"] == ABSTAIN],
    "harm_detection_recall": lambda rows: [
        r for r in rows if r["truth"] in HARM_LABELS and r["verdict"] == r["truth"]],
    "harm_not_blessed_rate": lambda rows: [
        r for r in rows if r["truth"] in HARM_LABELS and r["verdict"] != VERIFIED],
    "partial_remediation_recall": lambda rows: [
        r for r in rows if r["truth"] == TruthLabel.PARTIALLY_REMEDIATED.value
        and r["verdict"] == r["truth"]],
    "accuracy": lambda rows: [r for r in rows if r["verdict"] == r["truth"]],
}


def metric_block(rows: List[dict], with_intervals: bool = True) -> Dict[str, Any]:
    """Every rate, with its counts, a Wilson interval, and a cluster interval."""
    block: Dict[str, Any] = {"n": len(rows)}
    clusters: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        clusters[row["family"]].append(row)

    for name, fn in RATE_FUNCTIONS.items():
        numerator = len(_NUMERATORS[name](rows))
        denominator = len(_DENOMINATORS[name](rows))
        entry: Dict[str, Any] = {
            "value": fn(rows),
            "numerator": numerator,
            "denominator": denominator,
            "numerator_meaning": METRIC_DEFINITIONS[name]["numerator"],
            "denominator_meaning": METRIC_DEFINITIONS[name]["denominator"],
        }
        if with_intervals:
            lo, hi = wilson_interval(numerator, denominator)
            entry["wilson_ci95"] = [lo, hi] if denominator else None
            entry["cluster_bootstrap_ci95"] = cluster_bootstrap(dict(clusters), fn)
        block[name] = entry

    block["evidence_requests_per_case"] = {
        "value": requests_per_case(rows),
        "numerator": sum(len(r.get("evidence_requests", [])) for r in rows),
        "denominator": len(rows),
        "numerator_meaning": METRIC_DEFINITIONS["evidence_requests_per_case"]["numerator"],
        "denominator_meaning": METRIC_DEFINITIONS["evidence_requests_per_case"]["denominator"],
    }
    made = [q for r in rows for q in r.get("evidence_requests", [])]
    block["request_success_rate"] = {
        "value": request_success_rate(rows),
        "numerator": sum(1 for q in made if q.get("granted")), "denominator": len(made)}
    block["decision_relevant_request_rate"] = {
        "value": decision_relevant_rate(rows),
        "numerator": sum(1 for q in made if q.get("decision_relevant")), "denominator": len(made)}
    block["mean_latency_units"] = (
        sum(r.get("latency_units", 0.0) for r in rows) / len(rows) if rows else 0.0)
    block["verdict_distribution"] = {
        v: sum(1 for r in rows if r["verdict"] == v) for v in ALL_VERDICTS}
    return block


def confusion_matrix(rows: List[dict]) -> Dict[str, Dict[str, int]]:
    matrix = {t: {v: 0 for v in ALL_VERDICTS} for t in ALL_TRUTH_LABELS}
    for row in rows:
        matrix[row["truth"]][row["verdict"]] += 1
    return matrix


def active_recovery(rows_reference: List[dict], rows_active: List[dict]) -> Dict[str, Any]:
    """How much of Arm D's abstention Arm E converts into a correct answer."""
    by_id = {r["condition_id"]: r for r in rows_active}
    abstained = [r for r in rows_reference if r["verdict"] == ABSTAIN]
    recovered, recovered_wrong, new_assurance_errors = [], [], []
    for row in abstained:
        active = by_id.get(row["condition_id"])
        if active is None or active["verdict"] == ABSTAIN:
            continue
        if active["verdict"] == active["truth"]:
            recovered.append(active["condition_id"])
        else:
            recovered_wrong.append(active["condition_id"])
        if active["verdict"] == VERIFIED and active["truth"] != VERIFIED:
            new_assurance_errors.append(active["condition_id"])
    return {
        "reference_abstentions": len(abstained),
        "recovered_correct": len(recovered),
        "recovered_incorrect": len(recovered_wrong),
        "recovery_rate": _rate(len(recovered), len(abstained)),
        "recovery_rate_numerator": "reference-arm abstentions that the active arm answered correctly",
        "recovery_rate_denominator": "reference-arm abstentions",
        "new_false_assurances_created": len(new_assurance_errors),
        "new_false_assurance_condition_ids": sorted(new_assurance_errors)[:20],
    }


def paired_comparison(name_a: str, rows_a: List[dict], name_b: str, rows_b: List[dict],
                      error: str = "false_assurance") -> Dict[str, Any]:
    """McNemar over the identical set of conditions.

    error='false_assurance'  the error of interest is claiming verified wrongly
    error='unsafe_escape'    the error is waving through an actually-unsafe case
    error='wrong_verdict'    any disagreement with truth
    """
    by_id = {r["condition_id"]: r for r in rows_b}

    def is_error(row: dict) -> bool:
        if error == "false_assurance":
            return row["verdict"] == VERIFIED and row["truth"] != VERIFIED
        if error == "unsafe_escape":
            return row["truth"] in UNSAFE_LABELS and row["verdict"] == VERIFIED
        return row["verdict"] != row["truth"]

    b = c = 0
    only_a, only_b = [], []
    for row in rows_a:
        other = by_id.get(row["condition_id"])
        if other is None:
            continue
        ea, eb = is_error(row), is_error(other)
        if ea and not eb:
            b += 1
            only_a.append(row["condition_id"])
        elif eb and not ea:
            c += 1
            only_b.append(row["condition_id"])

    result = mcnemar(b, c)
    result.update({
        "comparison": f"{name_a} vs {name_b}",
        "error_of_interest": error,
        "paired_conditions": len([r for r in rows_a if r["condition_id"] in by_id]),
        "errors_only_in_first": only_a[:20],
        "errors_only_in_second": only_b[:20],
        "interpretation": significance_label(float(result["p_exact"]), int(result["n_discordant"])),
        "external_validity_note": "significance here describes this generated corpus only; "
                                  "conditions within a scenario family are correlated by construction",
    })
    return result


def score_everything(rows: List[dict]) -> Dict[str, Any]:
    by_arm: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        by_arm[row["arm"]].append(row)

    overall = {arm: metric_block(by_arm[arm]) for arm in ARMS if arm in by_arm}
    matrices = {arm: confusion_matrix(by_arm[arm]) for arm in ARMS if arm in by_arm}

    by_condition: Dict[str, Dict[str, Any]] = {}
    for arm, arm_rows in by_arm.items():
        groups: Dict[Any, List[dict]] = defaultdict(list)
        for row in arm_rows:
            groups[(row["coverage"], row["mechanism"])].append(row)
        by_condition[arm] = {
            f"c{int(cov * 100):03d}|{mech}": {
                **metric_block(group, with_intervals=False),
                "confusion_matrix": confusion_matrix(group),
            }
            for (cov, mech), group in sorted(groups.items(), key=lambda kv: (-kv[0][0], kv[0][1]))
        }

    by_family: Dict[str, Dict[str, Any]] = {}
    for arm, arm_rows in by_arm.items():
        groups = defaultdict(list)
        for row in arm_rows:
            groups[row["family"]].append(row)
        by_family[arm] = {fam: metric_block(group, with_intervals=False)
                          for fam, group in sorted(groups.items())}

    comparisons: List[Dict[str, Any]] = []
    pairs = [("A_STATUS_ONLY", "C_SCOPE_UNAWARE_INDEPENDENT"),
             ("B_TARGET_STATE", "C_SCOPE_UNAWARE_INDEPENDENT"),
             ("C_SCOPE_UNAWARE_INDEPENDENT", "D_SCOPE_AWARE_FAIL_CLOSED"),
             ("C_SCOPE_UNAWARE_INDEPENDENT", "E_ACTIVE_EVIDENCE"),
             ("D_SCOPE_AWARE_FAIL_CLOSED", "E_ACTIVE_EVIDENCE")]
    for first, second in pairs:
        if first not in by_arm or second not in by_arm:
            continue
        for error in ("false_assurance", "unsafe_escape", "wrong_verdict"):
            comparisons.append(paired_comparison(first, by_arm[first], second, by_arm[second], error))

    # Mechanism groupings.  UNDECLARED_GAP is kept apart from the five
    # mechanisms the v2 brief specifies, because it is an addition of this
    # experiment and it is the one gap no manifest can reveal.  Folding it into
    # the headline "adversarial" figure would quietly change what that figure
    # means.
    groups = {
        "adversarial_declared": lambda r: r["mechanism"] in ADVERSARIAL_DECLARED,
        "random_missing": lambda r: r["mechanism"] == "RANDOM_MISSING",
        "undeclared_gap": lambda r: r["mechanism"] == "UNDECLARED_GAP",
        "adversarial_all": lambda r: r["mechanism"] in ADVERSARIAL_DECLARED | {"UNDECLARED_GAP"},
        "full_coverage": lambda r: r["mechanism"] == "NONE",
    }
    by_group = {name: {arm: metric_block([r for r in by_arm[arm] if pred(r)])
                       for arm in ARMS if arm in by_arm}
                for name, pred in groups.items()}

    by_coverage = {}
    for arm, arm_rows in by_arm.items():
        buckets: Dict[Any, List[dict]] = defaultdict(list)
        for row in arm_rows:
            buckets[row["coverage"]].append(row)
        by_coverage[arm] = {f"{cov:.2f}": metric_block(rows_, with_intervals=False)
                            for cov, rows_ in sorted(buckets.items(), reverse=True)}

    by_mechanism = {}
    for arm, arm_rows in by_arm.items():
        buckets = defaultdict(list)
        for row in arm_rows:
            buckets[row["mechanism"]].append(row)
        by_mechanism[arm] = {mech: metric_block(rows_, with_intervals=False)
                             for mech, rows_ in sorted(buckets.items())}

    for group_name in ("adversarial_declared", "random_missing", "undeclared_gap"):
        pred = groups[group_name]
        for first, second in pairs:
            if first not in by_arm or second not in by_arm:
                continue
            cmp = paired_comparison(first, [r for r in by_arm[first] if pred(r)],
                                    second, [r for r in by_arm[second] if pred(r)],
                                    "unsafe_escape")
            cmp["mechanism_group"] = group_name
            comparisons.append(cmp)

    recovery = {}
    if "D_SCOPE_AWARE_FAIL_CLOSED" in by_arm and "E_ACTIVE_EVIDENCE" in by_arm:
        recovery = active_recovery(by_arm["D_SCOPE_AWARE_FAIL_CLOSED"], by_arm["E_ACTIVE_EVIDENCE"])

    return {
        "metric_definitions": METRIC_DEFINITIONS,
        "overall": overall,
        "confusion_matrices": matrices,
        "by_condition": by_condition,
        "by_family": by_family,
        "by_group": by_group,
        "by_coverage": by_coverage,
        "by_mechanism": by_mechanism,
        "paired_comparisons": comparisons,
        "active_recovery": recovery,
    }
