"""Result serialisation, manifest stability, reproducibility metadata."""
from __future__ import annotations

import csv
import json

from rvbench.manifest import build_manifest


def test_manifest_is_stable_across_reemission(root):
    from rvbench.corpus.emit import emit
    before = build_manifest(root)["manifest_sha256"]
    emit(root)
    after = build_manifest(root)["manifest_sha256"]
    assert before == after


def test_manifest_covers_all_three_case_files(root):
    m = build_manifest(root)
    assert {f["path"] for f in m["files"]} == {
        "cases/public/cases.json",
        "cases/simulation/scenarios.json",
        "cases/ground_truth/labels.json",
    }
    assert len(m["manifest_sha256"]) == 64


def test_raw_results_has_one_record_per_case_and_arm(root, experiment):
    raw = (root / "results" / "raw_results.jsonl").read_text().splitlines()
    lines = [json.loads(line) for line in raw if line.strip()]
    assert len(lines) == 48 * 3
    assert {r["arm"] for r in lines} == {"STATUS_ONLY", "TARGET_STATE", "INDEPENDENT_VERIFIER"}
    assert len({r["case_id"] for r in lines}) == 48


def test_raw_results_contain_no_ground_truth(root, experiment):
    text = (root / "results" / "raw_results.jsonl").read_text()
    assert "truth" not in text
    assert "ground_truth" not in text


def test_predictions_csv_is_wellformed(root, experiment):
    with (root / "results" / "predictions.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 144
    assert {"case_id", "truth", "arm", "predicted", "false_safe"} <= set(rows[0])


def test_metrics_json_round_trips(root, experiment):
    data = json.loads((root / "results" / "metrics.json").read_text())
    assert set(data["arms"]) == {"STATUS_ONLY", "TARGET_STATE", "INDEPENDENT_VERIFIER"}
    for arm in data["arms"].values():
        assert arm["n"] == 48
        assert 0.0 <= arm["false_safe_rate"] <= 1.0


def test_confusion_matrices_sum_to_case_count(root, experiment):
    data = json.loads((root / "results" / "confusion_matrices.json").read_text())
    for arm, matrix in data.items():
        total = sum(v for row in matrix.values() for v in row.values())
        assert total == 48, arm


def test_run_metadata_records_reproducibility_fields(root, experiment):
    meta = json.loads((root / "results" / "run_metadata.json").read_text())
    for key in ("experiment_version", "experiment_revision", "timestamp_utc", "git_commit_sha",
                "python_version", "dependencies", "random_seed", "case_manifest_sha256",
                "verifier_versions", "configuration"):
        assert key in meta, key
    assert meta["configuration"]["real_endpoint_adapters_enabled"] is False


def test_experiment_is_reproducible_across_runs(root):
    """Two full runs must agree on every prediction and every metric."""
    from rvbench.runner import run_predictions
    a = run_predictions(root)
    b = run_predictions(root)
    strip = lambda recs: [{k: v for k, v in r.items() if k != "latency_ms"} for r in recs]
    assert strip(a) == strip(b)


def test_false_safe_review_covers_every_false_safe(root, experiment):
    from rvbench.analysis.false_safe_review import write_review
    summary = write_review(root)
    expected = sum(m["false_safe_count"] for m in experiment["metrics"].values())
    assert summary["count"] == expected
