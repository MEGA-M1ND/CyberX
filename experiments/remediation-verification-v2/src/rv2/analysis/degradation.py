"""Degradation tables, CSVs, and curves."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..collect.conditions import COVERAGE_LEVELS
from ..vocab import ALL_TRUTH_LABELS, ALL_VERDICTS, ARMS
from .svg import small_multiples, write_svg

SHORT = {"A_STATUS_ONLY": "A status", "B_TARGET_STATE": "B target",
         "C_SCOPE_UNAWARE_INDEPENDENT": "C unaware", "D_SCOPE_AWARE_FAIL_CLOSED": "D scoped",
         "E_ACTIVE_EVIDENCE": "E active"}

CURVE_METRICS = [
    ("false_assurance_rate", "False assurance", "wrong VERIFIED / all VERIFIED claims"),
    ("unsafe_escape_rate", "Unsafe escape", "unsafe cases called VERIFIED / all unsafe cases"),
    ("abstention_rate", "Abstention", "INSUFFICIENT_EVIDENCE / all cases"),
    ("verified_recall", "Verified recall", "correct VERIFIED / all truly remediated cases"),
]


def _val(block: Dict[str, Any], metric: str) -> Optional[float]:
    entry = block.get(metric)
    return entry.get("value") if isinstance(entry, dict) else None


def write_degradation_csv(path: Path, results: Dict[str, Any]) -> Path:
    """Long-format: one row per arm x coverage x mechanism x metric."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["arm", "coverage", "mechanism", "metric", "value",
                         "numerator", "denominator", "n_conditions"])
        for arm, blocks in results["by_condition"].items():
            for key, block in blocks.items():
                coverage, mechanism = key.split("|", 1)
                coverage_value = int(coverage[1:]) / 100
                for metric in ["false_assurance_rate", "unsafe_escape_rate", "verified_precision",
                               "verified_recall", "abstention_rate", "harm_detection_recall",
                               "partial_remediation_recall", "accuracy"]:
                    entry = block[metric]
                    writer.writerow([arm, f"{coverage_value:.2f}", mechanism, metric,
                                     "" if entry["value"] is None else f"{entry['value']:.6f}",
                                     entry["numerator"], entry["denominator"], block["n"]])
                writer.writerow([arm, f"{coverage_value:.2f}", mechanism,
                                 "evidence_requests_per_case",
                                 f"{block['evidence_requests_per_case']['value']:.6f}",
                                 block["evidence_requests_per_case"]["numerator"],
                                 block["evidence_requests_per_case"]["denominator"], block["n"]])
    return Path(path)


def write_curves_csv(path: Path, results: Dict[str, Any]) -> Path:
    """Wide-format curve data: arm x coverage, aggregated over mechanisms."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["arm", "coverage", "n_conditions"] + [m for m, _, _ in CURVE_METRICS])
        for arm in ARMS:
            blocks = results["by_coverage"].get(arm, {})
            for coverage in COVERAGE_LEVELS:
                block = blocks.get(f"{coverage:.2f}")
                if not block:
                    continue
                row = [arm, f"{coverage:.2f}", block["n"]]
                for metric, _, _ in CURVE_METRICS:
                    value = _val(block, metric)
                    row.append("" if value is None else f"{value:.6f}")
                writer.writerow(row)
    return Path(path)


def write_results_csv(path: Path, rows: List[Dict[str, Any]]) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["condition_id", "partition", "family", "coverage", "mechanism",
                         "instance", "arm", "verdict", "truth", "correct", "false_assurance",
                         "unsafe_escape", "abstained", "achieved_coverage",
                         "evidence_requests", "latency_units", "reason_codes"])
        for row in rows:
            unsafe = row["truth"] in {"REMEDIATION_FAILED", "PARTIALLY_REMEDIATED", "NEW_SECURITY_RISK"}
            verified = row["verdict"] == "VERIFIED_REMEDIATED"
            writer.writerow([
                row["condition_id"], row["partition"], row["family"], f"{row['coverage']:.2f}",
                row["mechanism"], row["instance"], row["arm"], row["verdict"], row["truth"],
                int(row["verdict"] == row["truth"]),
                int(verified and row["truth"] != "VERIFIED_REMEDIATED"),
                int(unsafe and verified),
                int(row["verdict"] == "INSUFFICIENT_EVIDENCE"),
                "" if row.get("achieved_coverage") is None else f"{row['achieved_coverage']:.4f}",
                len(row.get("evidence_requests", [])), row.get("latency_units", 0),
                "|".join(row.get("reason_codes", [])),
            ])
    return Path(path)


def write_confusion_json(path: Path, results: Dict[str, Any]) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "axes": {"rows": "ground truth label", "columns": "predicted verdict",
                 "truth_labels": ALL_TRUTH_LABELS, "verdicts": ALL_VERDICTS},
        "overall": results["confusion_matrices"],
        "by_condition": {arm: {key: block["confusion_matrix"] for key, block in blocks.items()}
                         for arm, blocks in results["by_condition"].items()},
    }
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return Path(path)


def build_curves_svg(path: Path, results: Dict[str, Any]) -> Path:
    xs = list(COVERAGE_LEVELS)
    names = [SHORT[a] for a in ARMS]
    panels = []
    for metric, title, subtitle in CURVE_METRICS:
        series = []
        for arm in ARMS:
            blocks = results["by_coverage"].get(arm, {})
            series.append((SHORT[arm],
                           [_val(blocks.get(f"{c:.2f}", {}), metric) for c in xs]))
        panels.append({"title": title, "subtitle": subtitle, "xs": xs,
                       "series": series, "y_max": 1.0})
    svg = small_multiples(panels, names,
                          "Verification behaviour as evidence coverage falls (holdout partition)")
    return write_svg(path, svg)
