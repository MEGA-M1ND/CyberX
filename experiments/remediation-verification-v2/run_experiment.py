#!/usr/bin/env python3
"""Run Remediation Verification v2 end to end.

    python3 run_experiment.py              # dev + holdout, all artefacts and reports
    python3 run_experiment.py --holdout    # holdout only

Simulation only: no network, no real endpoint, no host changes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rv2.analysis.degradation import (  # noqa: E402
    build_curves_svg,
    write_confusion_json,
    write_curves_csv,
    write_degradation_csv,
    write_results_csv,
)
from rv2.analysis.reports import (  # noqa: E402
    evaluate_success_criteria,
    write_degradation_report,
    write_false_assurance_review,
    write_final_report,
    write_shared_design_threats,
)
from rv2.bench.run import run_metadata, run_partition  # noqa: E402
from rv2.vocab import ARMS  # noqa: E402

COMMANDS = [
    "python3 run_experiment.py",
    "python3 check_reproducibility.py",
    "pytest -q",
    "ruff check .",
]


def _slim(results: dict) -> dict:
    return {k: v for k, v in results.items() if k not in ("rows", "conditions")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--holdout", action="store_true",
                        help="run only the holdout partition")
    args = parser.parse_args()

    partitions = ["holdout"] if args.holdout else ["dev", "holdout"]
    results = {p: run_partition(ROOT, p) for p in partitions}
    manifests = {p: results[p]["manifest"] for p in partitions}
    metadata = run_metadata(ROOT, manifests, COMMANDS)

    holdout = results["holdout"]
    rows = holdout["rows"]
    criteria = evaluate_success_criteria(holdout)

    artifacts = ROOT / "artifacts"
    reports = ROOT / "reports"

    (artifacts / "results.json").write_text(json.dumps(
        {"run_metadata": metadata, "success_criteria": criteria,
         "holdout": _slim(holdout),
         **({"dev": _slim(results["dev"])} if "dev" in results else {})},
        indent=2, sort_keys=True, default=str) + "\n")
    (artifacts / "statistical-tests.json").write_text(json.dumps(
        {"note": "McNemar over identical conditions. Significance describes this generated "
                 "corpus only; conditions within a scenario family are correlated by construction.",
         "holdout": holdout["paired_comparisons"],
         "active_recovery": holdout["active_recovery"]},
        indent=2, sort_keys=True) + "\n")
    (artifacts / "run-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")

    write_results_csv(artifacts / "results.csv", rows)
    write_degradation_csv(artifacts / "degradation-by-condition.csv", holdout)
    write_curves_csv(artifacts / "degradation-curves.csv", holdout)
    write_confusion_json(artifacts / "confusion-matrices.json", holdout)
    build_curves_svg(reports / "degradation-curves.svg", holdout)

    write_final_report(reports / "final-report.md", holdout, rows, metadata, criteria)
    write_false_assurance_review(reports / "false-assurance-review.md", holdout, rows)
    write_degradation_report(reports / "collection-degradation.md", holdout)
    write_shared_design_threats(reports / "shared-design-threats.md", holdout)

    # ---- console summary ------------------------------------------------ #
    overall = holdout["overall"]
    print(f"\nholdout manifest SHA-256: {manifests['holdout']['manifest_sha256']}")
    print(f"conditions: {metadata['case_counts']['conditions_per_partition']} per partition x "
          f"{len(ARMS)} arms\n")
    header = f"{'arm':<30}{'false assurance':>20}{'unsafe escape':>18}{'abstain':>9}{'VR recall':>11}{'acc':>8}"
    print(header)
    for arm in ARMS:
        block = overall[arm]
        fa = block["false_assurance_rate"]
        ue = block["unsafe_escape_rate"]
        fa_text = f"{fa['numerator']}/{fa['denominator']}" + (
            "" if fa["value"] is None else f" {fa['value']:.3f}")
        ue_text = f"{ue['numerator']}/{ue['denominator']} {ue['value']:.3f}"
        print(f"{arm:<30}{fa_text:>20}{ue_text:>18}"
              f"{block['abstention_rate']['value']:>9.3f}"
              f"{(block['verified_recall']['value'] or 0):>11.3f}"
              f"{block['accuracy']['value']:>8.3f}")
    rec = holdout["active_recovery"]
    print(f"\nactive recovery: {rec['recovered_correct']}/{rec['reference_abstentions']} "
          f"({rec['recovery_rate']:.3f}) correct, {rec['recovered_incorrect']} incorrect, "
          f"{rec['new_false_assurances_created']} new false assurances")
    print(f"classification: {criteria['classification']} "
          f"({criteria['criteria_met']}/{criteria['criteria_total']} criteria met)")
    print(f"report: {reports / 'final-report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
