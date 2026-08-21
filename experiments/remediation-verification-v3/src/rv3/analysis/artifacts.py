"""Machine-readable artefacts."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from ..contracts.scope import CollectorContract


def write_json(path: Path, payload: Any) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    return Path(path)


def write_collector_contracts(path: Path, contracts: List[CollectorContract]) -> Path:
    return write_json(path, {
        "note": "Contracts marked MODEL_OF_VENDOR_DOCUMENTATION_UNVERIFIED have no implementation "
                "behind them and are the weakest evidence in this experiment.",
        "contracts": [c.to_dict() for c in sorted(contracts, key=lambda c: c.collector_id)],
    })


def write_gap_classifications(path: Path, rows) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["fixture_id", "family", "fact_id", "evidence_type", "decides",
                         "collector_id", "gap_class", "completeness_claimed", "covered",
                         "status", "registry_view", "hive", "user_scope", "path_root", "provider"])
        for row in rows:
            coords = row.coordinates
            writer.writerow([row.fixture_id, row.family, row.fact_id, row.evidence_type,
                             row.decides, row.collector_id, row.gap_class,
                             int(row.completeness_claimed), int(row.covered), row.status,
                             coords.get("registry_view") or "", coords.get("hive") or "",
                             coords.get("user_scope") or "", coords.get("path_root") or "",
                             coords.get("provider") or ""])
    return Path(path)


def write_results_csv(path: Path, results: Dict[str, Any]) -> Path:
    """One row per collector, wide format, every metric with its counts."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    metrics = ["decisive_undeclared_gap_rate", "fixture_undeclared_gap_rate",
               "false_coverage_claim_rate", "verification_feasibility",
               "unresolved_decisive_fact_rate"]
    with Path(path).open("w", newline="") as handle:
        writer = csv.writer(handle)
        header = ["collector_id", "measurement_status", "contract_basis", "claims_complete_for",
                  "silent_misses"]
        for metric in metrics:
            header += [f"{metric}_value", f"{metric}_numerator", f"{metric}_denominator"]
        writer.writerow(header)
        for cid, entry in sorted(results["per_collector"].items()):
            row = [cid, results["measurement_status"], entry["contract_basis"],
                   "|".join(entry["claims_complete_for"]), entry["silent_misses"]]
            for metric in metrics:
                item = entry[metric]
                row += ["" if item["value"] is None else f"{item['value']:.6f}",
                        item["numerator"], item["denominator"]]
            writer.writerow(row)
    return Path(path)


def write_raw_observations(path: Path, observations: Dict[str, Any], results: Dict[str, Any],
                           preflight_result: Dict[str, Any]) -> Path:
    return write_json(path, {
        "measurement_status": results["measurement_status"],
        "run_status": results["run_status"],
        "blocked_reason": results["blocked_reason"],
        "preflight": {k: v for k, v in preflight_result.items() if k != "rendered"},
        "note": ("No collector was executed, so there are no raw observations. The classifications "
                 "in gap-classifications.csv were deduced from collector contracts."
                 if not observations else
                 "Raw JSON emitted by each read-only collector on the lab VM."),
        "observations": observations,
    })
