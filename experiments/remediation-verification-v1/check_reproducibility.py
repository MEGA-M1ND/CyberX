#!/usr/bin/env python3
"""Reproducibility gate.

Fails if:
  * the case-manifest SHA-256 differs from the frozen value in FROZEN_MANIFEST
  * re-emitting the corpus changes any case file
  * two prediction passes disagree on any verdict, confidence, reason code, or evidence
  * a fresh scoring pass disagrees with the committed confusion matrices

Latency is excluded from the comparison: it is a wall-clock measurement, not a result.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rvbench.cases import load_ground_truth  # noqa: E402
from rvbench.corpus.emit import emit  # noqa: E402
from rvbench.manifest import MANIFEST_FILES, build_manifest  # noqa: E402
from rvbench.runner import run_predictions  # noqa: E402
from rvbench.scorer.scorer import score_arm  # noqa: E402

FROZEN = (ROOT / "FROZEN_MANIFEST").read_text().strip()


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    raise SystemExit(1)


def main() -> int:
    before = {rel: (ROOT / rel).read_bytes() for rel in MANIFEST_FILES}
    emit(ROOT)
    for rel, blob in before.items():
        if (ROOT / rel).read_bytes() != blob:
            fail(f"re-emitting the corpus changed {rel}")
    print("corpus re-emission is byte-identical")

    sha = build_manifest(ROOT)["manifest_sha256"]
    if sha != FROZEN:
        fail(f"case-manifest SHA-256 {sha} != frozen {FROZEN}")
    print(f"case-manifest SHA-256 matches FROZEN_MANIFEST: {sha}")

    strip = lambda recs: [{k: v for k, v in r.items() if k != "latency_ms"} for r in recs]
    a, b = run_predictions(ROOT), run_predictions(ROOT)
    if strip(a) != strip(b):
        fail("two prediction passes disagree")
    print(f"{len(a)} predictions reproduced exactly across two passes")

    truth = load_ground_truth(ROOT / "cases" / "ground_truth" / "labels.json")
    rows_by_arm: dict = {}
    for rec in a:
        gt = truth[rec["case_id"]]
        rows_by_arm.setdefault(rec["arm"], []).append(
            {**rec, "truth": gt.label, "category": gt.category, "rationale": gt.rationale}
        )
    fresh = {arm: score_arm(arm, rows)["confusion_matrix"] for arm, rows in rows_by_arm.items()}
    committed = json.loads((ROOT / "results" / "confusion_matrices.json").read_text())
    if fresh != committed:
        fail("fresh confusion matrices differ from the committed results")
    print("confusion matrices match the committed results")

    for arm, rows in sorted(rows_by_arm.items()):
        m = score_arm(arm, rows)
        print(f"  {arm:<22} false-safe {m['false_safe_count']:>2}/{m['n']} ({m['false_safe_rate']:.3f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
