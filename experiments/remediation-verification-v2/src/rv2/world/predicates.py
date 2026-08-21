"""Latent-side predicate evaluation.

Two-valued, total, and omniscient: the latent world holds every fact, so a
predicate over it is simply true or false.  There is no UNKNOWN here.

This is intentionally a *separate implementation* from
`rv2/obs/observed_predicates.py`, which is three-valued and has to reason about
provenance, freshness, scope, and disagreement.  Sharing one evaluator between
the oracle and the verifier would reintroduce exactly the shared-design coupling
v1's report flagged as its largest threat to validity.  The duplication is the
control.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .state import DeviceState, version_below

LEAF_OPS = {
    "package_version_below",
    "package_present",
    "package_absent",
    "registry_equals",
    "registry_not_equals",
    "registry_key_present",
    "service_running",
    "service_stopped",
    "service_startup_is",
    "file_present",
    "file_absent",
    "file_version_below",
    "patch_installed",
    "patch_missing",
    "patch_staged",
    "posture_flag_true",
    "posture_flag_equals",
}


class LatentPredicateError(ValueError):
    pass


def evaluate(node: Dict[str, Any], state: DeviceState) -> bool:
    op = node.get("op")
    if op == "any_of":
        return any(evaluate(child, state) for child in node["operands"])
    if op == "all_of":
        return all(evaluate(child, state) for child in node["operands"])
    if op == "not":
        return not evaluate(node["operand"], state)
    if op not in LEAF_OPS:
        raise LatentPredicateError(f"unknown latent predicate op: {op!r}")
    return _leaf(op, node, state)


def _leaf(op: str, node: Dict[str, Any], state: DeviceState) -> bool:
    if op.startswith("package_"):
        matches = [p for p in state.packages if p.name == node["package"]]
        if op == "package_version_below":
            return any(version_below(p.version, node["fixed_version"]) for p in matches)
        if op == "package_present":
            return any(p.version == node["version"] for p in matches)
        return not any(p.version == node["version"] for p in matches)

    if op.startswith("registry_"):
        present = node["path"] in state.registry
        if op == "registry_key_present":
            return present
        if op == "registry_equals":
            return present and state.registry[node["path"]] == node["value"]
        return (not present) or state.registry[node["path"]] != node["value"]

    if op.startswith("service_"):
        svc = state.services.get(node["service"])
        if svc is None:
            return False
        if op == "service_running":
            return svc.get("status") == "running"
        if op == "service_stopped":
            return svc.get("status") == "stopped"
        return svc.get("startup_type") == node["startup_type"]

    if op.startswith("file_"):
        entry = state.files.get(node["path"])
        if op == "file_present":
            return bool(entry and entry.get("exists"))
        if op == "file_absent":
            return not (entry and entry.get("exists"))
        if not entry or not entry.get("exists") or entry.get("version") is None:
            return False
        return version_below(entry["version"], node["fixed_version"])

    if op.startswith("patch_"):
        patch = state.patches.get(node["kb"], {"installed": False, "staged": False})
        if op == "patch_installed":
            return bool(patch.get("installed"))
        if op == "patch_staged":
            return bool(patch.get("staged"))
        return not patch.get("installed")

    if op == "posture_flag_true":
        return bool(state.security_posture.get(node["flag"]))
    if op == "posture_flag_equals":
        return state.security_posture.get(node["flag"]) == node["value"]

    raise LatentPredicateError(f"unhandled latent op {op!r}")


def top_level_components(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    """A vulnerability written as any_of[...] has independently fixable parts."""
    if node.get("op") == "any_of":
        return list(node["operands"])
    return [node]
