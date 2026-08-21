"""SHA-256 manifests.

Three separately hashed things, because they can go stale independently:

    generation config    the parameters that determine which conditions exist
    holdout manifest     the exact list of conditions and their seeds
    observations         the serialised observation packages the arms saw

Any change to any of them invalidates a previously reported holdout result.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(payload: Any) -> str:
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(generation_config: Dict[str, Any], conditions: List[Dict[str, Any]],
                   observations_path: Path, partition: str,
                   observations_digest: str = "") -> Dict[str, Any]:
    payload = {
        "experiment": "remediation-verification-v2",
        "partition": partition,
        "generation_config": generation_config,
        "generation_config_sha256": sha256_json(generation_config),
        "condition_count": len(conditions),
        "conditions_sha256": sha256_json(conditions),
        "observations_file": observations_path.name,
        # Digest of the uncompressed JSONL, so it does not depend on the local
        # zlib build.  The file on disk is gzipped with mtime=0 for size.
        "observations_sha256": observations_digest or sha256_file(observations_path),
        "observations_digest_scope": "uncompressed JSONL bytes",
    }
    payload["manifest_sha256"] = sha256_json(
        {k: v for k, v in payload.items() if k != "generation_config"})
    return payload


def write_manifest(path: Path, manifest: Dict[str, Any]) -> Dict[str, Any]:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest
