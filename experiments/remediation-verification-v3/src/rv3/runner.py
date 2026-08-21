"""Experiment runner.

Order of operations, and the reason for it:

    1  build the fixture catalog and freeze its manifest
    2  preflight: resolve machine identity, read gates, print planned actions
    3  if and only if every gate is open, provision the lab VM, run the real
       read-only collectors, and tear the fixtures down
    4  otherwise record BLOCKED_NOT_EXECUTED and fall back to the contract
       prediction, which is labelled PREDICTED everywhere it appears
    5  classify every (fixture, decisive fact, collector) triple
    6  score, and - on a real run - diff the measurement against the prediction

Step 4 is not a substitute for step 3.  A prediction derived from collector
contracts says what *should* happen if the contracts are accurate; the whole
value of a lab run is finding out where they are not.
"""
from __future__ import annotations

import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analysis.classify import classify_observed, classify_predicted, prediction_vs_measurement
from .analysis.metrics import score
from .contracts.catalog import IMPLEMENTED_CONTRACTS, contracts
from .contracts.scope import contract_hash_payload
from .fixtures.catalog import build_catalog
from .fixtures.manifest import build_fixture_manifest, provisioning_plan, sha256_json, write_json
from .lab.preflight import preflight
from .vocab import Mode, RunStatus

EXPERIMENT_REVISION = "3.0.0"


def git_sha(root: Path) -> str:
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root),
                              capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() if proc.returncode == 0 else "unavailable"
    except Exception:
        return "unavailable"


def run(root: Path, include_imports: bool = True,
        env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    root = Path(root)
    fixtures = build_catalog()
    collector_contracts = contracts(include_imports=include_imports)
    collector_ids = [c.collector_id for c in collector_contracts]

    manifest = build_fixture_manifest()
    plan = provisioning_plan()

    check = preflight(len(fixtures), collector_ids, with_setup=True, env=env)

    observations: Dict[str, Any] = {}
    measured_rows: List[Any] = []
    comparison: Optional[Dict[str, Any]] = None

    if check["may_proceed"]:  # pragma: no cover - requires a confirmed lab VM
        status = RunStatus.MEASURED_ON_LAB_VM.value
        mode = Mode.REAL_LAB.value
        from .collectors.real import provision_fixtures, remove_fixtures, run_collector
        plan_path = write_json(root / "manifests" / "provisioning-plan.json", plan)
        provisioned = provision_fixtures(root / "powershell", plan_path)
        manifest = build_fixture_manifest(provisioned.get("observed_ground_truth", []))
        try:
            for fixture in fixtures:
                for collector_id in [c.collector_id for c in IMPLEMENTED_CONTRACTS]:
                    result = run_collector(collector_id, root / "powershell",
                                           fixture.collector_view())
                    observations.setdefault(fixture.fixture_id, {})[collector_id] = result.payload
        finally:
            remove_fixtures(root / "powershell", plan_path)
        for fixture in fixtures:
            measured_rows.extend(classify_observed([fixture], observations[fixture.fixture_id]))
    else:
        status = RunStatus.BLOCKED_NOT_EXECUTED.value
        mode = Mode.DRY_RUN.value

    predicted_rows = classify_predicted(fixtures, collector_ids)
    rows = measured_rows or predicted_rows
    if measured_rows:  # pragma: no cover - requires a confirmed lab VM
        comparison = prediction_vs_measurement(predicted_rows, measured_rows)

    results = score(rows, fixtures, collector_ids)
    results.update({
        "mode": mode,
        "run_status": status,
        "measurement_status": (RunStatus.MEASURED_ON_LAB_VM.value if measured_rows
                               else RunStatus.PREDICTED_FROM_CONTRACTS.value),
        "blocked_reason": check["blocked_reason"],
        "prediction_vs_measurement": comparison,
        "fixture_manifest": manifest,
        "provisioning_plan_sha256": plan["plan_sha256"],
        "collector_contracts_sha256": sha256_json(contract_hash_payload(collector_contracts)),
        "classifications_sha256": sha256_json([r.to_dict() for r in rows]),
    })
    return {
        "results": results,
        "rows": rows,
        "fixtures": fixtures,
        "contracts": collector_contracts,
        "preflight": check,
        "manifest": manifest,
        "plan": plan,
        "observations": observations,
    }


def run_metadata(root: Path, results: Dict[str, Any], commands: List[str]) -> Dict[str, Any]:
    return {
        "experiment": "remediation-verification-v3",
        "experiment_revision": EXPERIMENT_REVISION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit_sha": git_sha(root),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "dependencies": "Python standard library only; no third-party runtime dependencies",
        "mode": results["mode"],
        "run_status": results["run_status"],
        "measurement_status": results["measurement_status"],
        "blocked_reason": results["blocked_reason"],
        "fixture_manifest_sha256": results["fixture_manifest"]["manifest_sha256"],
        "fixture_specifications_sha256": results["fixture_manifest"]["full_specifications_sha256"],
        "generation_config_sha256": results["fixture_manifest"]["generation_config_sha256"],
        "provisioning_plan_sha256": results["provisioning_plan_sha256"],
        "collector_contracts_sha256": results["collector_contracts_sha256"],
        "classifications_sha256": results["classifications_sha256"],
        "commands": commands,
        "real_collection_performed": results["run_status"] == RunStatus.MEASURED_ON_LAB_VM.value,
        "network_access_required": False,
        "gates": {"ALLOW_WINDOWS_FIXTURE_SETUP": "required for provisioning",
                  "ALLOW_REAL_WINDOWS_LAB": "required for any real collection",
                  "RV3_LAB_CONFIRMATION": "must equal the target machine's hostname"},
    }
