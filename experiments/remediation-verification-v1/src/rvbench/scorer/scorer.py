"""Scoring.  This is the ONLY module that reads the ground-truth labels."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from ..models import ALL_VERDICTS, Verdict
from .stats import mcnemar, significance_label, wilson_interval

SAFE = Verdict.VERIFIED_REMEDIATED.value


def is_false_safe(predicted: str, truth: str) -> bool:
    """A false-safe is a claim of remediation that the endpoint does not support."""
    return predicted == SAFE and truth != SAFE


def is_false_failure(predicted: str, truth: str) -> bool:
    return truth == SAFE and predicted != SAFE


def confusion_matrix(pairs: List[Dict[str, str]]) -> Dict[str, Dict[str, int]]:
    m = {t: {p: 0 for p in ALL_VERDICTS} for t in ALL_VERDICTS}
    for row in pairs:
        m[row["truth"]][row["predicted"]] += 1
    return m


def _prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def score_arm(arm: str, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(rows)
    pairs = [{"truth": r["truth"], "predicted": r["predicted"]} for r in rows]

    correct = sum(1 for r in rows if r["predicted"] == r["truth"])
    fs = [r["case_id"] for r in rows if is_false_safe(r["predicted"], r["truth"])]
    ff = [r["case_id"] for r in rows if is_false_failure(r["predicted"], r["truth"])]
    ie = [r["case_id"] for r in rows if r["predicted"] == Verdict.INSUFFICIENT_EVIDENCE.value]

    per_class: Dict[str, Dict[str, float]] = {}
    for cls in ALL_VERDICTS:
        tp = sum(1 for r in rows if r["truth"] == cls and r["predicted"] == cls)
        fp = sum(1 for r in rows if r["truth"] != cls and r["predicted"] == cls)
        fn = sum(1 for r in rows if r["truth"] == cls and r["predicted"] != cls)
        per_class[cls] = {**_prf(tp, fp, fn), "support": sum(1 for r in rows if r["truth"] == cls)}

    supported = [c for c in ALL_VERDICTS if per_class[c]["support"] > 0]
    macro_f1 = sum(per_class[c]["f1"] for c in supported) / len(supported) if supported else 0.0

    def detect_rate(truth_label: str) -> Optional[float]:
        subset = [r for r in rows if r["truth"] == truth_label]
        if not subset:
            return None
        return sum(1 for r in subset if r["predicted"] == truth_label) / len(subset)

    def category_flag_rate(prefix: str) -> Optional[float]:
        """Fraction of a category's cases the arm declined to call remediated."""
        subset = [r for r in rows if r["category"].startswith(prefix)]
        if not subset:
            return None
        return sum(1 for r in subset if r["predicted"] != SAFE) / len(subset)

    fs_lo, fs_hi = wilson_interval(len(fs), n)
    acc_lo, acc_hi = wilson_interval(correct, n)

    return {
        "arm": arm,
        "n": n,
        "accuracy": correct / n if n else 0.0,
        "accuracy_ci95": [acc_lo, acc_hi],
        "macro_f1": macro_f1,
        "verified_remediated_precision": per_class[SAFE]["precision"],
        "verified_remediated_recall": per_class[SAFE]["recall"],
        "false_safe_count": len(fs),
        "false_safe_rate": len(fs) / n if n else 0.0,
        "false_safe_rate_ci95": [fs_lo, fs_hi],
        "false_safe_case_ids": fs,
        "false_failure_count": len(ff),
        "false_failure_rate": len(ff) / n if n else 0.0,
        "false_failure_case_ids": ff,
        "insufficient_evidence_count": len(ie),
        "insufficient_evidence_rate": len(ie) / n if n else 0.0,
        "regression_detection_rate": detect_rate(Verdict.REGRESSION_INTRODUCED.value),
        "partial_remediation_detection_rate": detect_rate(Verdict.PARTIALLY_REMEDIATED.value),
        "new_security_risk_detection_rate": detect_rate(Verdict.NEW_SECURITY_RISK.value),
        "insufficient_evidence_detection_rate": detect_rate(Verdict.INSUFFICIENT_EVIDENCE.value),
        "fleet_partial_success_detection_rate": category_flag_rate("G_"),
        "mean_latency_ms": sum(r["latency_ms"] for r in rows) / n if n else 0.0,
        "per_class": per_class,
        "confusion_matrix": confusion_matrix(pairs),
        "by_category": _by_category(rows),
    }


def _by_category(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[r["category"]].append(r)
    for cat, subset in sorted(groups.items()):
        out[cat] = {
            "n": len(subset),
            "correct": sum(1 for r in subset if r["predicted"] == r["truth"]),
            "false_safe": sum(1 for r in subset if is_false_safe(r["predicted"], r["truth"])),
            "predictions": Counter(r["predicted"] for r in subset),
        }
    return out


def paired_comparison(arm_a: str, rows_a: List[Dict[str, Any]],
                      arm_b: str, rows_b: List[Dict[str, Any]],
                      metric: str = "false_safe") -> Dict[str, Any]:
    """McNemar on the same 48 cases, per-case paired.

    metric='false_safe' -> the error of interest is a false-safe prediction
    metric='accuracy'   -> the error of interest is any wrong verdict
    """
    by_id_b = {r["case_id"]: r for r in rows_b}
    b = c = 0
    a_only, b_only = [], []
    for ra in rows_a:
        rb = by_id_b[ra["case_id"]]
        if metric == "false_safe":
            ea = is_false_safe(ra["predicted"], ra["truth"])
            eb = is_false_safe(rb["predicted"], rb["truth"])
        else:
            ea = ra["predicted"] != ra["truth"]
            eb = rb["predicted"] != rb["truth"]
        if ea and not eb:
            b += 1
            a_only.append(ra["case_id"])
        elif eb and not ea:
            c += 1
            b_only.append(ra["case_id"])
    result = mcnemar(b, c)
    result.update({
        "comparison": f"{arm_a} vs {arm_b}",
        "metric": metric,
        "errors_unique_to_" + arm_a: a_only,
        "errors_unique_to_" + arm_b: b_only,
        "interpretation": significance_label(float(result["p_exact"]), int(result["n_discordant"])),
    })
    return result
