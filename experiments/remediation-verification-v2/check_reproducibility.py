#!/usr/bin/env python3
"""Reproducibility gate.

Fails if:
  * the holdout manifest SHA-256 differs from the frozen value in FROZEN_MANIFEST
  * regenerating the holdout conditions changes any seed
  * two independent prediction passes disagree on any verdict, reason code, or
    evidence request
  * a fresh scoring pass disagrees with the committed confusion matrices

Wall-clock latency and the run timestamp are excluded and documented as runtime
data; everything else must be byte-identical.
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rv2.bench.generate import generate, generation_config  # noqa: E402
from rv2.bench.manifest import sha256_json  # noqa: E402
from rv2.bench.run import run_predictions  # noqa: E402
from rv2.metrics.metrics import confusion_matrix  # noqa: E402
from rv2.oracle.truth import derive_truth  # noqa: E402
from rv2.world.scenarios import build_world  # noqa: E402

VOLATILE = {"latency_units"}


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def strip(records):
    return [{k: v for k, v in r.items() if k not in VOLATILE} for r in records]


def main() -> int:
    frozen_manifest = (ROOT / "FROZEN_MANIFEST").read_text().strip()
    manifest_path = ROOT / "manifests" / "holdout-manifest.json"
    if not manifest_path.exists():
        fail("no holdout manifest on disk; run `python3 run_experiment.py` first")
    manifest = json.loads(manifest_path.read_text())

    if manifest["manifest_sha256"] != frozen_manifest:
        fail(f"holdout manifest {manifest['manifest_sha256']} != frozen {frozen_manifest}")
    print(f"holdout manifest matches FROZEN_MANIFEST: {frozen_manifest}")

    conditions = generate("holdout")
    if sha256_json([c.to_dict() for c in conditions]) != manifest["conditions_sha256"]:
        fail("regenerated holdout conditions do not match the manifest")
    if sha256_json(generation_config()) != manifest["generation_config_sha256"]:
        fail("generation config does not match the manifest")
    print(f"{len(conditions)} holdout conditions and the generation config reproduce exactly")

    first, _ = run_predictions(conditions)
    second, _ = run_predictions(conditions)
    if strip(first) != strip(second):
        fail("two prediction passes disagree")
    print(f"{len(first)} predictions reproduced exactly across two independent passes")

    frozen_path = ROOT / "artifacts" / "predictions-holdout.jsonl.gz"
    with gzip.open(frozen_path, "rt") as fh:
        on_disk = [json.loads(line) for line in fh if line.strip()]
    if strip(on_disk) != strip(first):
        fail("frozen predictions on disk differ from a fresh run")
    print("frozen predictions on disk match a fresh run")

    truth = {c.condition_id: derive_truth(build_world(c.family, c.world_seed, c.condition_id)).label
             for c in conditions}
    for record in first:
        record["truth"] = truth[record["condition_id"]]
    fresh = {}
    for record in first:
        fresh.setdefault(record["arm"], []).append(record)
    fresh_matrices = {arm: confusion_matrix(rows) for arm, rows in fresh.items()}

    committed = json.loads((ROOT / "artifacts" / "confusion-matrices.json").read_text())["overall"]
    if fresh_matrices != committed:
        fail("fresh confusion matrices differ from the committed artefacts")
    print("confusion matrices match the committed artefacts")

    for arm in sorted(fresh):
        rows = fresh[arm]
        escapes = sum(1 for r in rows
                      if r["truth"] in {"REMEDIATION_FAILED", "PARTIALLY_REMEDIATED",
                                        "NEW_SECURITY_RISK"}
                      and r["verdict"] == "VERIFIED_REMEDIATED")
        print(f"  {arm:<30} unsafe escapes {escapes:>4}/{len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
