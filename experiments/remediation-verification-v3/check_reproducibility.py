#!/usr/bin/env python3
"""Reproducibility gate.

Fails if:
  * the fixture manifest SHA-256 differs from the frozen value in FROZEN_MANIFEST
  * rebuilding the fixture catalog changes any fixture hash
  * two independent classification passes disagree
  * a fresh scoring pass disagrees with the committed artefacts
  * real collection is somehow reachable on this host
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rv3.analysis.classify import classify_predicted  # noqa: E402
from rv3.contracts.catalog import ALL_CONTRACTS  # noqa: E402
from rv3.contracts.scope import contract_hash_payload  # noqa: E402
from rv3.fixtures.catalog import build_catalog  # noqa: E402
from rv3.fixtures.manifest import build_fixture_manifest, provisioning_plan, sha256_json  # noqa: E402
from rv3.lab.gates import LabGateError, read_gates  # noqa: E402
from rv3.vocab import RunStatus  # noqa: E402


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def main() -> int:
    frozen = (ROOT / "FROZEN_MANIFEST").read_text().strip()
    manifest = build_fixture_manifest()
    if manifest["manifest_sha256"] != frozen:
        fail(f"fixture manifest {manifest['manifest_sha256']} != frozen {frozen}")
    print(f"fixture manifest matches FROZEN_MANIFEST: {frozen}")

    first, second = build_catalog(), build_catalog()
    if [s.fixture_hash() for s in first] != [s.fixture_hash() for s in second]:
        fail("rebuilding the fixture catalog produced different hashes")
    if sha256_json([s.to_dict() for s in first]) != manifest["full_specifications_sha256"]:
        fail("fixture specifications do not match the manifest")
    print(f"{len(first)} fixtures and {sum(len(s.decisive_facts) for s in first)} decisive facts "
          "reproduce exactly")

    plan = provisioning_plan()
    if plan["plan_sha256"] != sha256_json(plan["operations"]):
        fail("provisioning plan hash does not cover its own operations")
    print(f"provisioning plan reproduces: {plan['operation_count']} operations, "
          f"{plan['plan_sha256'][:16]}")

    ids = [c.collector_id for c in ALL_CONTRACTS]
    pass_a = classify_predicted(first, ids)
    pass_b = classify_predicted(second, ids)
    if [r.to_dict() for r in pass_a] != [r.to_dict() for r in pass_b]:
        fail("two classification passes disagree")
    print(f"{len(pass_a)} classifications reproduce exactly across two passes")

    contracts_sha = sha256_json(contract_hash_payload(ALL_CONTRACTS))
    committed_path = ROOT / "artifacts" / "run-metadata.json"
    if not committed_path.exists():
        fail("no run metadata on disk; run `python3 run_experiment.py` first")
    committed = json.loads(committed_path.read_text())
    for key, value in (("collector_contracts_sha256", contracts_sha),
                       ("fixture_manifest_sha256", manifest["manifest_sha256"]),
                       ("provisioning_plan_sha256", plan["plan_sha256"]),
                       ("classifications_sha256", sha256_json([r.to_dict() for r in pass_a]))):
        if committed.get(key) != value:
            fail(f"{key} on disk ({committed.get(key)}) != freshly computed ({value})")
    print("collector contracts, plan, and classification hashes match the committed artefacts")

    csv_path = ROOT / "artifacts" / "gap-classifications.csv"
    with csv_path.open() as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != len(pass_a):
        fail(f"gap-classifications.csv has {len(rows)} rows, expected {len(pass_a)}")
    print(f"gap-classifications.csv matches: {len(rows)} rows")

    if committed["run_status"] == RunStatus.MEASURED_ON_LAB_VM.value:
        print("committed artefacts record a MEASURED lab run")
    else:
        print(f"committed artefacts record {committed['run_status']}: "
              f"{committed['blocked_reason']}")

    gates = read_gates()
    if gates.platform_system != "Windows":
        from rv3.collectors.real import run_collector
        try:
            run_collector("A_UNINSTALL_REGISTRY", ROOT / "powershell",
                          {"fixture_id": "x", "file_root": "C:", "registry_root": "S",
                           "arp_prefix": "P"})
        except LabGateError:
            print("real collection is unreachable on this host, as required")
        else:
            fail("real collection was NOT blocked on a non-Windows host")

    for cid in ids:
        entry = next(c for c in ALL_CONTRACTS if c.collector_id == cid)
        misses = sum(1 for r in pass_a if r.collector_id == cid and r.is_silent_miss)
        print(f"  {cid:<26} silent misses {misses:>3}  claims_complete_for="
              f"{entry.claims_complete_for or '[]'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
