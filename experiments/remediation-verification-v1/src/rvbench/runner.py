"""Experiment runner.

Order of operations is the experimental control, so it is written out
explicitly and asserted rather than left as a convention:

    1  load PUBLIC cases          (verifier-visible)
    2  load SIMULATION scenarios  (harness-only)
    3  apply remediation
    4  run Arm A / Arm B / Arm C  -> predictions
    5  FREEZE predictions to disk
    6  only now: load GROUND TRUTH
    7  score, compare, write artefacts
"""
from __future__ import annotations

import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .adapters.simulated import SimulatedEndpointAdapter
from .cases import load_ground_truth, load_public_cases, load_scenarios
from .corpus.build import SEED
from .manifest import write_manifest
from .models import EXPERIMENT_VERSION
from .scorer.scorer import paired_comparison, score_arm
from .verifiers import build_arms
from .verifiers.base import VerifierInput

EXPERIMENT_REVISION = "1.0.0"


def _git_sha(root: Path) -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root),
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() if out.returncode == 0 else "unavailable"
    except Exception:
        return "unavailable"


def run_predictions(root: Path) -> List[Dict[str, Any]]:
    """Steps 1-4.  Returns one record per (case, arm).  Ground truth is not
    imported, opened, or referenced anywhere in this function."""
    cases = load_public_cases(root / "cases" / "public" / "cases.json")
    scenarios = load_scenarios(root / "cases" / "simulation" / "scenarios.json")
    arms = build_arms()

    records: List[Dict[str, Any]] = []
    for case in cases:
        scenario = scenarios[case.case_id]
        for verifier in arms:
            # A fresh adapter per arm: no arm can observe another arm's probing.
            adapter = SimulatedEndpointAdapter(scenario)
            execution = adapter.apply_remediation()
            out = verifier.run(VerifierInput(case=case, adapter=adapter))
            records.append(
                {
                    "case_id": case.case_id,
                    "arm": verifier.arm,
                    "verifier_version": verifier.version,
                    "predicted": out.verdict,
                    "confidence": out.confidence,
                    "reason_codes": out.reason_codes,
                    "evidence": out.evidence,
                    "latency_ms": out.latency_ms,
                    "execution_exit_code": execution.exit_code,
                    "deployment_status": execution.deployment_status,
                }
            )
    return records


def run(root: Path) -> Dict[str, Any]:
    root = Path(root)
    results_dir = root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    manifest = write_manifest(root)

    # ---- steps 1-4: predictions, with ground truth untouched --------------
    records = run_predictions(root)

    # ---- step 5: freeze -------------------------------------------------
    raw_path = results_dir / "raw_results.jsonl"
    with raw_path.open("w") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    # ---- step 6: reveal ground truth ------------------------------------
    truth = load_ground_truth(root / "cases" / "ground_truth" / "labels.json")

    frozen = [json.loads(line) for line in raw_path.read_text().splitlines() if line.strip()]
    assert frozen == json.loads(json.dumps(records)), "frozen predictions differ from in-memory predictions"

    rows_by_arm: Dict[str, List[Dict[str, Any]]] = {}
    for rec in frozen:
        gt = truth[rec["case_id"]]
        row = {
            "case_id": rec["case_id"],
            "arm": rec["arm"],
            "predicted": rec["predicted"],
            "truth": gt.label,
            "category": gt.category,
            "confidence": rec["confidence"],
            "reason_codes": rec["reason_codes"],
            "latency_ms": rec["latency_ms"],
            "rationale": gt.rationale,
            "evidence": rec["evidence"],
        }
        rows_by_arm.setdefault(rec["arm"], []).append(row)

    # ---- step 7: score --------------------------------------------------
    metrics = {arm: score_arm(arm, rows) for arm, rows in rows_by_arm.items()}

    comparisons: List[Dict[str, Any]] = []
    order = ["STATUS_ONLY", "TARGET_STATE", "INDEPENDENT_VERIFIER"]
    for i in range(len(order)):
        for j in range(i + 1, len(order)):
            a, b = order[i], order[j]
            for metric in ("false_safe", "accuracy"):
                cmp = paired_comparison(a, rows_by_arm[a], b, rows_by_arm[b], metric=metric)
                cmp["delta_false_safe_rate"] = metrics[b]["false_safe_rate"] - metrics[a]["false_safe_rate"]
                cmp["delta_accuracy"] = metrics[b]["accuracy"] - metrics[a]["accuracy"]
                cmp["delta_verified_remediated_precision"] = (
                    metrics[b]["verified_remediated_precision"] - metrics[a]["verified_remediated_precision"]
                )
                comparisons.append(cmp)

    run_meta = {
        "experiment_version": EXPERIMENT_VERSION,
        "experiment_revision": EXPERIMENT_REVISION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit_sha": _git_sha(root),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "dependencies": "standard library only (no third-party runtime dependencies)",
        "random_seed": SEED,
        "case_manifest_sha256": manifest["manifest_sha256"],
        "case_manifest_files": manifest["files"],
        "verifier_versions": {v.arm: v.version for v in build_arms()},
        "remediation_source": "deterministic corpus (Phase 1)",
        "llm_provider": None,
        "llm_model": None,
        "configuration": {
            "arms": order,
            "case_count": len(truth),
            "adapter": "SimulatedEndpointAdapter",
            "real_endpoint_adapters_enabled": False,
        },
    }

    _write_artifacts(results_dir, rows_by_arm, metrics, comparisons, run_meta)
    return {"metrics": metrics, "comparisons": comparisons, "run_metadata": run_meta,
            "rows_by_arm": rows_by_arm, "manifest": manifest}


def _write_artifacts(results_dir: Path, rows_by_arm, metrics, comparisons, run_meta) -> None:
    import csv

    order = ["STATUS_ONLY", "TARGET_STATE", "INDEPENDENT_VERIFIER"]

    with (results_dir / "predictions.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "category", "truth", "arm", "predicted", "correct",
                    "false_safe", "confidence", "latency_ms", "reason_codes"])
        for arm in order:
            for r in rows_by_arm[arm]:
                w.writerow([
                    r["case_id"], r["category"], r["truth"], arm, r["predicted"],
                    int(r["predicted"] == r["truth"]),
                    int(r["predicted"] == "VERIFIED_REMEDIATED" and r["truth"] != "VERIFIED_REMEDIATED"),
                    r["confidence"], r["latency_ms"], "|".join(r["reason_codes"]),
                ])

    with (results_dir / "case_failures.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["case_id", "category", "arm", "truth", "predicted", "failure_kind",
                    "reason_codes", "ground_truth_rationale"])
        for arm in order:
            for r in rows_by_arm[arm]:
                if r["predicted"] == r["truth"]:
                    continue
                if r["predicted"] == "VERIFIED_REMEDIATED":
                    kind = "FALSE_SAFE"
                elif r["truth"] == "VERIFIED_REMEDIATED":
                    kind = "FALSE_FAILURE"
                else:
                    kind = "MISCLASSIFIED"
                w.writerow([r["case_id"], r["category"], arm, r["truth"], r["predicted"], kind,
                            "|".join(r["reason_codes"]), r["rationale"]])

    slim = {arm: {k: v for k, v in m.items() if k != "confusion_matrix"} for arm, m in metrics.items()}
    for m in slim.values():
        m["by_category"] = {c: {**d, "predictions": dict(d["predictions"])} for c, d in m["by_category"].items()}
    (results_dir / "metrics.json").write_text(json.dumps(
        {"run_metadata": run_meta, "arms": slim, "paired_comparisons": comparisons},
        indent=2, sort_keys=True) + "\n")

    (results_dir / "confusion_matrices.json").write_text(json.dumps(
        {arm: metrics[arm]["confusion_matrix"] for arm in order}, indent=2, sort_keys=True) + "\n")

    (results_dir / "run_metadata.json").write_text(json.dumps(run_meta, indent=2, sort_keys=True) + "\n")
