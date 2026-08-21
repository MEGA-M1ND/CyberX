"""Structured review record for every false-safe prediction.

Section 22 of the experiment brief: for each false-safe we record the case, the
starting vulnerable state, what the remediation actually did, what the
management tool reported, the post-remediation state, why the arm believed the
endpoint was safe, the real vulnerability predicate, and the signal that was
missing.  These records are generated from the frozen predictions, so the
write-up cannot drift from the data.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..adapters.simulated import SimulatedEndpointAdapter
from ..cases import load_ground_truth, load_public_cases, load_scenarios

# What each arm structurally cannot see.  Keyed by arm, then by the reason the
# case defeats it.
MISSING_SIGNAL: Dict[str, str] = {
    "STATUS_ONLY": "any post-remediation security state at all; the arm only reads execution metadata",
    "TARGET_STATE": "an independent vulnerability predicate; the arm only checks that the intended change landed",
    "INDEPENDENT_VERIFIER": "see per-case note; the collector reported a complete picture that was not complete",
}


def build_review(root: Path) -> List[Dict[str, Any]]:
    root = Path(root)
    cases = {c.case_id: c for c in load_public_cases(root / "cases" / "public" / "cases.json")}
    scenarios = load_scenarios(root / "cases" / "simulation" / "scenarios.json")
    truth = load_ground_truth(root / "cases" / "ground_truth" / "labels.json")

    records: List[Dict[str, Any]] = []
    raw = (root / "results" / "raw_results.jsonl").read_text().splitlines()
    for line in raw:
        if not line.strip():
            continue
        rec = json.loads(line)
        gt = truth[rec["case_id"]]
        if not (rec["predicted"] == "VERIFIED_REMEDIATED" and gt.label != "VERIFIED_REMEDIATED"):
            continue

        case = cases[rec["case_id"]]
        scenario = scenarios[rec["case_id"]]
        adapter = SimulatedEndpointAdapter(scenario)
        adapter.apply_remediation()

        env = scenario.env()
        if rec["arm"] == "INDEPENDENT_VERIFIER":
            bits = []
            if env.blind_spot_package_versions:
                bits.append(f"inventory omits package versions {env.blind_spot_package_versions}")
            if env.blind_spot_registry_paths:
                bits.append(f"registry collection scope omits {env.blind_spot_registry_paths}")
            if env.blind_spot_files:
                bits.append(f"file collection omits {env.blind_spot_files}")
            if env.blind_spot_flags:
                bits.append(f"posture snapshot omits security flags {env.blind_spot_flags}")
            missing = "; ".join(bits) or MISSING_SIGNAL[rec["arm"]]
            if env.collector_note:
                missing += f" (collector: {env.collector_note})"
        else:
            missing = MISSING_SIGNAL[rec["arm"]]

        records.append(
            {
                "case_id": case.case_id,
                "title": case.title,
                "failure_category": gt.category,
                "arm_that_failed": rec["arm"],
                "initial_vulnerable_state": scenario.initial_states[0],
                "remediation_action": scenario.remediation_ops[0],
                "execution_status": scenario.execution_result,
                "post_remediation_state_device0": adapter._true_state(0).to_dict(),
                "post_reboot_projection_device0": adapter._true_post_reboot(0).to_dict(),
                "why_verifier_believed_safe": rec["reason_codes"],
                "verifier_evidence": rec["evidence"],
                "actual_vulnerability_predicate": case.vulnerability_predicate,
                "ground_truth_label": gt.label,
                "ground_truth_rationale": gt.rationale,
                "missing_signal": missing,
            }
        )
    return records


def write_review(root: Path) -> Dict[str, Any]:
    root = Path(root)
    records = build_review(root)
    (root / "results" / "false_safe_review.json").write_text(
        json.dumps({"false_safe_reviews": records}, indent=2, sort_keys=True) + "\n"
    )

    by_arm: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        by_arm.setdefault(r["arm_that_failed"], []).append(r)

    lines: List[str] = [
        "# Manual false-safe review",
        "",
        "Every prediction of `VERIFIED_REMEDIATED` against a ground-truth label that is",
        "not `VERIFIED_REMEDIATED`, one entry per (case, arm).  Generated from",
        "`results/raw_results.jsonl` and the frozen case corpus.",
        "",
        f"Total false-safe predictions across all arms: **{len(records)}**",
        "",
    ]
    for arm in ("STATUS_ONLY", "TARGET_STATE", "INDEPENDENT_VERIFIER"):
        rows = by_arm.get(arm, [])
        lines += [f"## {arm} - {len(rows)} false-safe predictions", ""]
        if not rows:
            lines += ["_None._", ""]
            continue
        lines += ["| Case | Category | Ground truth | Why the arm said safe | Missing signal |",
                  "| --- | --- | --- | --- | --- |"]
        for r in rows:
            why = ", ".join(r["why_verifier_believed_safe"])
            lines.append(
                f"| `{r['case_id']}` | {r['failure_category']} | {r['ground_truth_label']} | {why} | {r['missing_signal']} |"
            )
        lines.append("")

    (root / "reports" / "false-safe-review.md").write_text("\n".join(lines) + "\n")
    return {"count": len(records), "by_arm": {k: len(v) for k, v in by_arm.items()}}
