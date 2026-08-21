"""Artefacts, reproducibility, and the v1/v2 regression guard."""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from rv3.contracts.catalog import ALL_CONTRACTS, IMPORT_CONTRACTS
from rv3.contracts.scope import VENDOR_DOC_MODEL, contract_hash_payload
from rv3.fixtures.manifest import build_fixture_manifest, sha256_json
from rv3.vocab import RunStatus


def _artifact(root: Path, name: str) -> Path:
    path = root / "artifacts" / name
    if not path.exists():
        pytest.skip("run `python3 run_experiment.py` first")
    return path


def test_frozen_manifest_matches_the_catalog(root):
    frozen = (root / "FROZEN_MANIFEST").read_text().strip()
    assert build_fixture_manifest()["manifest_sha256"] == frozen


def test_every_required_artifact_exists(root):
    for name in ("fixture-manifest.json", "collector-contracts.json", "raw-observations.json",
                 "results.json", "results.csv", "gap-classifications.csv", "run-metadata.json"):
        _artifact(root, name)


def test_every_required_report_exists(root):
    for name in ("final-report.md", "collector-gap-matrix.md", "undeclared-gap-review.md",
                 "cross-collector-recovery.md", "safety-and-lab-procedure.md",
                 "simulation-to-windows-transfer.md"):
        path = root / "reports" / name
        if not path.exists():
            pytest.skip("run `python3 run_experiment.py` first")
        assert path.read_text().strip()


def test_run_metadata_records_the_measurement_status(root):
    metadata = json.loads(_artifact(root, "run-metadata.json").read_text())
    for key in ("experiment", "experiment_revision", "timestamp_utc", "git_commit_sha",
                "python_version", "platform", "mode", "run_status", "measurement_status",
                "fixture_manifest_sha256", "collector_contracts_sha256",
                "provisioning_plan_sha256", "classifications_sha256", "gates", "commands"):
        assert key in metadata, key
    assert metadata["network_access_required"] is False
    assert metadata["real_collection_performed"] == (
        metadata["run_status"] == RunStatus.MEASURED_ON_LAB_VM.value)


def test_reports_label_predicted_results_as_predicted(root):
    """A dry run must never read as a measurement."""
    metadata = json.loads(_artifact(root, "run-metadata.json").read_text())
    if metadata["run_status"] == RunStatus.MEASURED_ON_LAB_VM.value:
        pytest.skip("this run measured a real lab VM")
    for name in ("final-report.md", "collector-gap-matrix.md", "undeclared-gap-review.md",
                 "cross-collector-recovery.md", "simulation-to-windows-transfer.md"):
        text = (root / "reports" / name).read_text()
        assert "BLOCKED_NOT_EXECUTED" in text, name
        assert "PREDICTED FROM COLLECTOR CONTRACTS" in text, name


def test_final_report_withholds_the_classification_on_a_dry_run(root):
    metadata = json.loads(_artifact(root, "run-metadata.json").read_text())
    if metadata["run_status"] == RunStatus.MEASURED_ON_LAB_VM.value:
        pytest.skip("this run measured a real lab VM")
    results = json.loads(_artifact(root, "results.json").read_text())
    assert results["decision_rule"]["classification"] == "WITHHELD"
    assert results["decision_rule"]["predicted_classification"]
    assert "must not be reported as a result" in results["decision_rule"]["classification_note"]


def test_raw_observations_are_empty_when_nothing_ran(root):
    metadata = json.loads(_artifact(root, "run-metadata.json").read_text())
    payload = json.loads(_artifact(root, "raw-observations.json").read_text())
    if metadata["run_status"] == RunStatus.MEASURED_ON_LAB_VM.value:
        pytest.skip("this run measured a real lab VM")
    assert payload["observations"] == {}
    assert payload["run_status"] == RunStatus.BLOCKED_NOT_EXECUTED.value


def test_gap_classifications_csv_covers_every_pair(root, classifications):
    with _artifact(root, "gap-classifications.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(classifications)
    assert {"fixture_id", "fact_id", "collector_id", "gap_class", "completeness_claimed"} <= set(rows[0])


def test_results_csv_has_one_row_per_collector(root):
    with _artifact(root, "results.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(ALL_CONTRACTS)
    assert all(row["measurement_status"] for row in rows)


def test_vendor_adapters_are_flagged_as_unverified(root):
    payload = json.loads(_artifact(root, "collector-contracts.json").read_text())
    modelled = [c for c in payload["contracts"] if c["basis"] == VENDOR_DOC_MODEL]
    assert len(modelled) == len(IMPORT_CONTRACTS)
    assert "weakest evidence" in payload["note"]


def test_contract_hash_is_stable():
    assert sha256_json(contract_hash_payload(ALL_CONTRACTS)) == \
           sha256_json(contract_hash_payload(list(reversed(ALL_CONTRACTS))))


def test_reproducibility_gate_passes(root):
    proc = subprocess.run([sys.executable, "check_reproducibility.py"], cwd=str(root),
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ------------------------------------------------------------------ regression
@pytest.mark.parametrize("experiment", ["remediation-verification-v1", "remediation-verification-v2"])
def test_earlier_experiments_still_pass(root, experiment):
    """v1 and v2 are frozen artefacts; v3 must not disturb them."""
    directory = root.parent / experiment
    if not directory.exists():
        pytest.skip(f"{experiment} not present")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=str(directory),
                          capture_output=True, text=True, timeout=900)
    if "No module named pytest" in (proc.stdout + proc.stderr):
        pytest.skip("pytest is not importable from this interpreter")
    assert proc.returncode == 0, proc.stdout[-3000:]


@pytest.mark.parametrize("experiment", ["remediation-verification-v1", "remediation-verification-v2"])
def test_earlier_manifests_are_unchanged(root, experiment):
    directory = root.parent / experiment
    if not directory.exists():
        pytest.skip(f"{experiment} not present")
    proc = subprocess.run([sys.executable, "check_reproducibility.py"], cwd=str(directory),
                          capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-3000:]
