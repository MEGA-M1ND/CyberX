"""Immutable case-manifest hashing.

The manifest covers all three case files - public, simulation, and ground
truth - so that "the corpus" means exactly one byte sequence.  Any edit to any
case, including a label, changes the manifest SHA-256 and therefore invalidates
a previously reported result.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

MANIFEST_FILES = [
    "cases/public/cases.json",
    "cases/simulation/scenarios.json",
    "cases/ground_truth/labels.json",
]


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_manifest(root: Path) -> Dict[str, Any]:
    root = Path(root)
    entries: List[Dict[str, Any]] = []
    for rel in MANIFEST_FILES:
        p = root / rel
        entries.append({"path": rel, "sha256": file_sha256(p), "bytes": p.stat().st_size})
    payload = {"experiment": "remediation-verification-v1", "files": entries}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


def write_manifest(root: Path) -> Dict[str, Any]:
    manifest = build_manifest(root)
    out = Path(root) / "cases" / "MANIFEST.json"
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest
