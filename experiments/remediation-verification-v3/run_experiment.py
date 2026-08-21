#!/usr/bin/env python3
"""Run Remediation Verification v3.

    python3 run_experiment.py                 # preflight, then run or block, then report
    python3 run_experiment.py --preflight-only  # print the preflight and stop

On anything other than a confirmed disposable Windows lab VM this prints the
preflight, records BLOCKED_NOT_EXECUTED, and falls back to a contract-derived
prediction that is labelled as such in every artefact and every report.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rv3.analysis.artifacts import (  # noqa: E402
    write_collector_contracts,
    write_gap_classifications,
    write_json,
    write_raw_observations,
    write_results_csv,
)
from rv3.analysis.reports import (  # noqa: E402
    evaluate_decision_rule,
    write_cross_collector_recovery,
    write_final_report,
    write_gap_matrix,
    write_safety_procedure,
    write_transfer_report,
    write_undeclared_gap_review,
)
from rv3.fixtures.manifest import write_json as write_manifest_json  # noqa: E402
from rv3.lab.preflight import write_preflight  # noqa: E402
from rv3.runner import run, run_metadata  # noqa: E402
from rv3.vocab import RunStatus  # noqa: E402

COMMANDS = [
    "python3 run_experiment.py",
    "python3 check_reproducibility.py",
    "pytest -q",
    "ruff check .",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true",
                        help="print the preflight and exit without running anything")
    args = parser.parse_args()

    out = run(ROOT)
    preflight_result = out["preflight"]
    print(preflight_result["rendered"])
    write_preflight(ROOT / "artifacts" / "preflight.txt", preflight_result)
    if args.preflight_only:
        return 0

    results, rows, fixtures = out["results"], out["rows"], out["fixtures"]
    metadata = run_metadata(ROOT, results, COMMANDS)
    decision = evaluate_decision_rule(results)

    artifacts, reports, manifests = ROOT / "artifacts", ROOT / "reports", ROOT / "manifests"

    write_manifest_json(manifests / "fixture-manifest.json", out["manifest"])
    write_manifest_json(manifests / "provisioning-plan.json", out["plan"])
    write_json(artifacts / "fixture-manifest.json", out["manifest"])
    write_collector_contracts(artifacts / "collector-contracts.json", out["contracts"])
    write_raw_observations(artifacts / "raw-observations.json", out["observations"], results,
                           preflight_result)
    write_json(artifacts / "results.json",
               {"run_metadata": metadata, "decision_rule": decision, "results": results})
    write_results_csv(artifacts / "results.csv", results)
    write_gap_classifications(artifacts / "gap-classifications.csv", rows)
    write_json(artifacts / "run-metadata.json", metadata)

    write_final_report(reports / "final-report.md", results, rows, fixtures, metadata, decision,
                       preflight_result)
    write_gap_matrix(reports / "collector-gap-matrix.md", results, rows)
    write_undeclared_gap_review(reports / "undeclared-gap-review.md", results, rows, fixtures)
    write_cross_collector_recovery(reports / "cross-collector-recovery.md", results, rows)
    write_safety_procedure(reports / "safety-and-lab-procedure.md", results, preflight_result,
                           out["plan"])
    write_transfer_report(reports / "simulation-to-windows-transfer.md", results)

    per = results["per_collector"]
    print(f"\nmeasurement status: {results['measurement_status']}")
    print(f"fixture manifest SHA-256: {out['manifest']['manifest_sha256']}")
    print(f"{out['manifest']['fixture_count']} fixtures / "
          f"{out['manifest']['decisive_fact_count']} decisive facts / {len(per)} collectors\n")
    print(f"{'collector':<26}{'undeclared gap':>18}{'silent':>8}{'decided':>9}{'unresolved':>12}")
    for cid, entry in per.items():
        gap = entry["decisive_undeclared_gap_rate"]
        value = "n/a" if gap["value"] is None else f"{gap['value']:.3f}"
        print(f"{cid:<26}{gap['numerator']:>4}/{gap['denominator']:<4}{value:>8}"
              f"{entry['silent_misses']:>8}"
              f"{entry['verification_feasibility']['numerator']:>6}/40"
              f"{entry['unresolved_decisive_fact_rate']['numerator']:>8}/48")
    rescue = results["cross_collector_rescue_rate"]
    active = results["active_request_success_rate"]
    print(f"\ncross-collector rescue: {rescue['numerator']}/{rescue['denominator']} "
          f"({(rescue['value'] or 0):.3f})")
    print(f"active-request success: {active['numerator']}/{active['denominator']}")
    print(f"remaining false assurance after composite: "
          f"{results['remaining_false_assurance_rate']['numerator']}/"
          f"{results['remaining_false_assurance_rate']['denominator']}")
    print(f"\ndecision rule: {decision['classification']} "
          f"(predicted {decision['predicted_classification']}, "
          f"{decision['criteria_met']}/{decision['criteria_total']} criteria)")
    if results["run_status"] == RunStatus.BLOCKED_NOT_EXECUTED.value:
        print("\n*** BLOCKED_NOT_EXECUTED: no real Windows collection was performed. ***")
        print("*** Every figure above is PREDICTED FROM COLLECTOR CONTRACTS. ***")
    print(f"report: {reports / 'final-report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
