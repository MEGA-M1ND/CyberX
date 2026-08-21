"""Emit the corpus to disk and derive the hidden ground-truth labels.

Ground truth is *computed* by running each scenario through the simulator and
applying scorer/ground_truth.derive() to the resulting true state.  Nobody
hand-labels an outcome, so no label can quietly disagree with the simulation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ..adapters.simulated import SimulatedEndpointAdapter
from ..cases import PublicCase, Scenario
from ..scorer.ground_truth import derive
from .build import build


def _write(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def emit(root: Path) -> Dict[str, Path]:
    root = Path(root)
    cases = build()

    public: List[Dict[str, Any]] = []
    scenarios: List[Dict[str, Any]] = []
    labels: List[Dict[str, Any]] = []

    for entry in cases:
        public.append(entry["public"])
        scenarios.append(entry["scenario"])

        case = PublicCase.from_dict(entry["public"])
        scenario = Scenario.from_dict(entry["scenario"])
        adapter = SimulatedEndpointAdapter(scenario)
        adapter.apply_remediation()

        verdict, rationale = derive(
            case=case,
            true_states=adapter._true_states_all(),
            true_post_reboot=[adapter._true_post_reboot(i) for i in range(adapter.device_count)],
            devices_targeted=adapter.get_execution_result().devices_targeted,
            unavailable_evidence=adapter.unavailable_evidence(),
        )
        labels.append(
            {
                "case_id": case.case_id,
                "label": verdict,
                "category": entry["category"],
                "rationale": rationale,
                "notes": entry["public"].get("notes", ""),
            }
        )

    paths = {
        "public": root / "cases" / "public" / "cases.json",
        "simulation": root / "cases" / "simulation" / "scenarios.json",
        "ground_truth": root / "cases" / "ground_truth" / "labels.json",
    }
    _write(paths["public"], {"cases": public})
    _write(paths["simulation"], {"scenarios": scenarios})
    _write(paths["ground_truth"], {"ground_truth": labels})
    return paths


if __name__ == "__main__":  # pragma: no cover
    here = Path(__file__).resolve().parents[3]
    for k, v in emit(here).items():
        print(f"{k}: {v}")
