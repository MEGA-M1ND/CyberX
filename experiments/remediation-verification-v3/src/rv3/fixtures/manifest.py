"""Frozen, hashed fixture manifest.

Two hashes matter and they answer different questions:

    fixture_hash       covers one fixture completely, ground truth included, so a
                       silently edited expectation changes it
    manifest_sha256    covers the whole corpus plus the generation parameters

On a real run the provisioner returns `observed_ground_truth` - what the machine
actually reported after each fixture was created - and that is folded in as a
third hash.  Ground truth then rests on the specification *and* a direct
observation, which is the point of provisioning-time validation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..vocab import FAMILIES
from .catalog import INSTANCES_PER_FAMILY, build_catalog
from .spec import FixtureSpec


def sha256_json(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def generation_config() -> Dict[str, Any]:
    return {
        "families": list(FAMILIES),
        "instances_per_family": INSTANCES_PER_FAMILY,
        "fixture_id_rule": "sha256('rv3|<family>|<index>')[:16], prefixed 'fx-'",
        "lab_file_root": r"C:\RV3Lab",
        "lab_registry_root": r"SOFTWARE\RV3Lab",
        "stub_binary_source": r"C:\Windows\System32\notepad.exe",
        "excluded_mechanisms": ["Win32_Product"],
    }


def build_fixture_manifest(observed: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    catalog: List[FixtureSpec] = build_catalog()
    entries = [{"fixture_id": spec.fixture_id,
                "family": spec.family,
                "fixture_hash": spec.fixture_hash(),
                "decisive_fact_count": len(spec.decisive_facts),
                "expected_vulnerable": spec.expected_vulnerable,
                "expected_persistent_after_reboot": spec.expected_persistent_after_reboot,
                "expected_regression": spec.expected_regression}
               for spec in catalog]
    config = generation_config()
    payload: Dict[str, Any] = {
        "experiment": "remediation-verification-v3",
        "fixture_count": len(catalog),
        "family_count": len({s.family for s in catalog}),
        "decisive_fact_count": sum(len(s.decisive_facts) for s in catalog),
        "generation_config": config,
        "generation_config_sha256": sha256_json(config),
        "fixtures": entries,
        "fixtures_sha256": sha256_json(entries),
        "full_specifications_sha256": sha256_json([s.to_dict() for s in catalog]),
    }
    if observed is not None:
        payload["provisioning_observations"] = observed
        payload["provisioning_observations_sha256"] = sha256_json(observed)
        payload["ground_truth_basis"] = "specification plus direct observation at provisioning time"
    else:
        payload["provisioning_observations"] = None
        payload["ground_truth_basis"] = (
            "specification only; no lab VM was provisioned, so no direct observation exists")
    payload["manifest_sha256"] = sha256_json(
        {k: v for k, v in payload.items() if k not in ("generation_config", "fixtures")})
    return payload


def provisioning_plan() -> Dict[str, Any]:
    """Ordered operations the PowerShell provisioner consumes, plus cleanup."""
    catalog = build_catalog()
    setup: List[Dict[str, Any]] = []
    cleanup: List[Dict[str, Any]] = []
    for spec in catalog:
        for op in spec.setup_ops:
            setup.append({"fixture_id": spec.fixture_id, **op.to_dict()})
        for op in spec.cleanup_ops:
            cleanup.append({"fixture_id": spec.fixture_id, **op.to_dict()})
    return {
        "experiment": "remediation-verification-v3",
        "warning": "Applying this plan WRITES to the target machine. Disposable lab VM only.",
        "operations": setup,
        "cleanup_operations": cleanup,
        "operation_count": len(setup),
        "plan_sha256": sha256_json(setup),
    }


def write_json(path: Path, payload: Any) -> Path:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return Path(path)
