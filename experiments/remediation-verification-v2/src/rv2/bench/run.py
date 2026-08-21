"""Benchmark harness.

The order below is the experimental control, so it is written out and asserted
rather than left as an intention:

    1  generate conditions            (seeds only; no world built yet)
    2  build the latent world         (harness side)
    3  collect evidence               (harness side)
    4  serialise the observation packages and hash them
    5  run every arm on its own view  -> predictions
    6  FREEZE predictions to disk
    7  only now: ask the oracle
    8  join, score, and write artefacts

Steps 1-6 never import or call the oracle.  A test asserts that from the source
text of `run_predictions`.
"""
from __future__ import annotations

import gzip
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from ..collect.collector import EvidenceService
from ..obs.package import ObservationPackage
from ..verifiers import ACTIVE_ARMS, FLAT_VIEW_ARMS, build_arms
from ..world.scenarios import build_world
from ..world.state import LatentWorld
from .generate import CaseCondition, generate, generation_config
from .manifest import build_manifest, sha256_bytes, sha256_json, write_manifest

EXPERIMENT_REVISION = "2.0.0"


def git_sha(root: Path) -> str:
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root),
                              capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() if proc.returncode == 0 else "unavailable"
    except Exception:
        return "unavailable"


def build_condition(condition: CaseCondition) -> Tuple[LatentWorld, ObservationPackage]:
    world = build_world(condition.family, condition.world_seed, condition.opaque_id)
    service = EvidenceService(world, condition.coverage, condition.mechanism, condition.condition_seed)
    return world, service.build_package()


def run_predictions(conditions: List[CaseCondition]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Steps 2-5.  Returns (prediction records, serialised observation packages).

    The oracle is not imported, opened, or called anywhere in this function.
    """
    arms = build_arms()
    records: List[Dict[str, Any]] = []
    packages: List[Dict[str, Any]] = []

    for condition in conditions:
        world = build_world(condition.family, condition.world_seed, condition.opaque_id)

        reference_service = EvidenceService(world, condition.coverage, condition.mechanism,
                                            condition.condition_seed)
        reference = reference_service.build_package()
        packages.append({"opaque_id": condition.opaque_id, "package": reference.to_dict()})
        true_coverage = reference_service.plan.achieved_coverage()

        for arm in arms:
            # A fresh service per arm: the active arm mutates collection state,
            # and no arm may observe another arm's probing.
            service = EvidenceService(world, condition.coverage, condition.mechanism,
                                      condition.condition_seed)
            package = service.build_package()
            view = package.flat_view() if arm.arm in FLAT_VIEW_ARMS else package
            channel = service if arm.arm in ACTIVE_ARMS else None
            decision = arm.run(view, channel)

            records.append({
                "condition_id": condition.condition_id,
                "partition": condition.partition,
                "family": condition.family,
                "coverage": condition.coverage,
                "mechanism": condition.mechanism,
                "instance": condition.instance,
                "arm": arm.arm,
                "arm_version": arm.version,
                "verdict": decision.verdict,
                "confidence": decision.confidence,
                "reason_codes": decision.reason_codes,
                "latency_units": decision.latency_units,
                "evidence_requests": decision.evidence_requests,
                # The real figure, from the private damage plan - not the
                # collector's self-report, which UNDECLARED_GAP makes untrue.
                "achieved_coverage": true_coverage,
                "declared_coverage": (package.manifest.declared_coverage
                                      if package.manifest else None),
                "items_observed": len(view.items),
            })
    return records, packages


def run_partition(root: Path, partition: str) -> Dict[str, Any]:
    root = Path(root)
    conditions = generate(partition)

    # ---- steps 2-5 ---------------------------------------------------- #
    records, packages = run_predictions(conditions)

    # ---- step 4/6: serialise observations and freeze predictions ------- #
    cases_dir = root / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    observations_path = cases_dir / f"{partition}-observations.jsonl.gz"
    payload = "".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n"
                      for entry in packages).encode()
    # mtime=0 so the archive is byte-identical between runs; the manifest hashes
    # the *uncompressed* bytes so the digest does not depend on zlib's version.
    with gzip.GzipFile(filename="", mode="wb", fileobj=observations_path.open("wb"),
                       mtime=0, compresslevel=9) as gz:
        gz.write(payload)
    observations_digest = sha256_bytes(payload)

    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    frozen_path = artifacts / f"predictions-{partition}.jsonl.gz"
    frozen_payload = "".join(json.dumps(record, sort_keys=True) + "\n"
                             for record in records).encode()
    with gzip.GzipFile(filename="", mode="wb", fileobj=frozen_path.open("wb"),
                       mtime=0, compresslevel=9) as gz:
        gz.write(frozen_payload)

    manifest = build_manifest(generation_config(), [c.to_dict() for c in conditions],
                              observations_path, partition,
                              observations_digest=observations_digest)
    write_manifest(root / "manifests" / f"{partition}-manifest.json", manifest)

    # ---- step 7: reveal ground truth ----------------------------------- #
    # Imported here, below the freeze, so the ordering is visible in the source
    # rather than merely intended.
    from ..metrics.metrics import score_everything
    from ..oracle.truth import derive_truth

    truths: Dict[str, Dict[str, Any]] = {}
    for condition in conditions:
        world = build_world(condition.family, condition.world_seed, condition.opaque_id)
        truth = derive_truth(world)
        truths[condition.condition_id] = {
            "label": truth.label, "rationale": truth.rationale, "detail": truth.detail}

    with gzip.open(frozen_path, "rt") as fh:
        frozen = [json.loads(line) for line in fh if line.strip()]
    assert frozen == json.loads(json.dumps(records)), "frozen predictions differ from in-memory"

    for record in frozen:
        record["truth"] = truths[record["condition_id"]]["label"]
        record["truth_rationale"] = truths[record["condition_id"]]["rationale"]

    # ---- step 8: score -------------------------------------------------- #
    results = score_everything(frozen)
    results["manifest"] = manifest
    results["conditions"] = [c.to_dict() for c in conditions]
    results["truth_sha256"] = sha256_json(truths)
    results["rows"] = frozen
    return results


def run_metadata(root: Path, manifests: Dict[str, Dict[str, Any]], commands: List[str]) -> Dict[str, Any]:
    from .generate import MASTER_SEED, counts
    return {
        "experiment": "remediation-verification-v2",
        "experiment_revision": EXPERIMENT_REVISION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit_sha": git_sha(root),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "dependencies": "Python standard library only; no third-party runtime dependencies",
        "master_seed": MASTER_SEED,
        "case_counts": counts(),
        "manifest_sha256": {k: v["manifest_sha256"] for k, v in manifests.items()},
        "generation_config_sha256": {k: v["generation_config_sha256"] for k, v in manifests.items()},
        "observations_sha256": {k: v["observations_sha256"] for k, v in manifests.items()},
        "conditions_sha256": {k: v["conditions_sha256"] for k, v in manifests.items()},
        "commands": commands,
        "real_endpoint_adapters_enabled": False,
        "network_access_required": False,
    }
