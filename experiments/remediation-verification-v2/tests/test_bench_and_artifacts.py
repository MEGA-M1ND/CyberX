"""Generation, freeze discipline, and artefact serialisation."""
from __future__ import annotations

import csv
import gzip
import json

from rv2.bench.generate import INSTANCES_PER_CELL, PARTITIONS, counts, generate, generation_config, stable_seed
from rv2.bench.manifest import sha256_json
from rv2.collect.conditions import COVERAGE_LEVELS, MECHANISMS
from rv2.vocab import ARMS
from rv2.world.scenarios import FAMILIES


def test_condition_count_meets_the_required_minimum():
    stats = counts()
    assert stats["conditions_per_partition"] >= 240
    expected = len(FAMILIES) * (1 + (len(COVERAGE_LEVELS) - 1) * len(MECHANISMS)) * INSTANCES_PER_CELL
    assert stats["conditions_per_partition"] == expected


def test_every_family_coverage_and_mechanism_appears():
    conditions = generate("holdout")
    assert {c.family for c in conditions} == set(FAMILIES)
    assert {c.coverage for c in conditions} == set(COVERAGE_LEVELS)
    below_full = {c.mechanism for c in conditions if c.coverage < 1.0}
    assert below_full == set(MECHANISMS)
    assert {c.mechanism for c in conditions if c.coverage >= 1.0} == {"NONE"}


def test_condition_ids_are_unique_within_a_partition():
    for partition in PARTITIONS:
        ids = [c.condition_id for c in generate(partition)]
        assert len(ids) == len(set(ids))


def test_seeds_are_stable_and_order_independent():
    assert stable_seed("a", 1) == stable_seed("a", 1)
    assert stable_seed("a", 1) != stable_seed("a", 2)
    first = [c.world_seed for c in generate("holdout")]
    second = [c.world_seed for c in generate("holdout")]
    assert first == second


def test_dev_and_holdout_share_no_seeds():
    dev = {c.world_seed for c in generate("dev")}
    holdout = {c.world_seed for c in generate("holdout")}
    assert not (dev & holdout)


def test_opaque_ids_hide_the_condition_identity():
    for condition in generate("holdout")[:50]:
        assert condition.family not in condition.opaque_id
        assert condition.mechanism not in condition.opaque_id
        assert condition.opaque_id.startswith("obs-")


def test_generation_config_hash_is_stable():
    assert sha256_json(generation_config()) == sha256_json(generation_config())


def test_predictions_reproduce_across_two_passes():
    from rv2.bench.run import run_predictions
    conditions = generate("dev")[:60]
    first, _ = run_predictions(conditions)
    second, _ = run_predictions(conditions)
    strip = lambda records: [{k: v for k, v in r.items() if k != "latency_units"} for r in records]
    assert strip(first) == strip(second)


def test_each_arm_gets_a_fresh_collection_service():
    """Arm E mutates collection state; no other arm may see it."""
    from rv2.bench.run import run_predictions
    conditions = [c for c in generate("dev")
                  if c.mechanism == "DECISIVE_FIELD_MISSING" and c.coverage == 0.6][:6]
    records, _ = run_predictions(conditions)
    by_condition = {}
    for record in records:
        by_condition.setdefault(record["condition_id"], {})[record["arm"]] = record
    for arms in by_condition.values():
        assert arms["D_SCOPE_AWARE_FAIL_CLOSED"]["items_observed"] == \
               arms["E_ACTIVE_EVIDENCE"]["items_observed"]


def test_frozen_predictions_and_artifacts_agree(root, scored_dev):
    path = root / "artifacts" / "predictions-dev.jsonl.gz"
    with gzip.open(path, "rt") as fh:
        frozen = [json.loads(line) for line in fh if line.strip()]
    assert len(frozen) == counts()["conditions_per_partition"] * len(ARMS)
    assert {r["arm"] for r in frozen} == set(ARMS)


def test_frozen_predictions_contain_no_truth(root, scored_dev):
    path = root / "artifacts" / "predictions-dev.jsonl.gz"
    with gzip.open(path, "rt") as fh:
        text = fh.read()
    assert '"truth"' not in text


def test_results_csv_is_wellformed(root):
    path = root / "artifacts" / "results.csv"
    if not path.exists():
        import pytest
        pytest.skip("run `python3 run_experiment.py` first")
    with path.open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == counts()["conditions_per_partition"] * len(ARMS)
    assert {"condition_id", "arm", "verdict", "truth", "false_assurance",
            "unsafe_escape", "abstained"} <= set(rows[0])
    assert all(row["partition"] == "holdout" for row in rows)


def test_curves_csv_covers_every_arm_and_level(root):
    path = root / "artifacts" / "degradation-curves.csv"
    if not path.exists():
        import pytest
        pytest.skip("run `python3 run_experiment.py` first")
    with path.open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == len(ARMS) * len(COVERAGE_LEVELS)


def test_confusion_matrices_total_to_the_condition_count(root):
    path = root / "artifacts" / "confusion-matrices.json"
    if not path.exists():
        import pytest
        pytest.skip("run `python3 run_experiment.py` first")
    data = json.loads(path.read_text())
    for arm, matrix in data["overall"].items():
        total = sum(v for row in matrix.values() for v in row.values())
        assert total == counts()["conditions_per_partition"], arm


def test_run_metadata_records_reproducibility_fields(root):
    path = root / "artifacts" / "run-metadata.json"
    if not path.exists():
        import pytest
        pytest.skip("run `python3 run_experiment.py` first")
    metadata = json.loads(path.read_text())
    for key in ("experiment", "experiment_revision", "timestamp_utc", "git_commit_sha",
                "python_version", "platform", "dependencies", "master_seed", "case_counts",
                "manifest_sha256", "generation_config_sha256", "observations_sha256", "commands"):
        assert key in metadata, key
    assert metadata["real_endpoint_adapters_enabled"] is False
    assert metadata["network_access_required"] is False


def test_holdout_manifest_matches_the_frozen_hash(root):
    path = root / "manifests" / "holdout-manifest.json"
    if not path.exists():
        import pytest
        pytest.skip("run `python3 run_experiment.py` first")
    manifest = json.loads(path.read_text())
    assert manifest["manifest_sha256"] == (root / "FROZEN_MANIFEST").read_text().strip()
    assert manifest["condition_count"] == counts()["conditions_per_partition"]
