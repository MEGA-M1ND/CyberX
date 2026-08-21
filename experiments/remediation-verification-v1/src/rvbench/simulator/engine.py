"""Deterministic remediation-action engine.

A remediation action is a list of ops.  Applying ops to an EndpointState is a
pure, total function: no randomness, no clock, no I/O.  Two runs with the same
inputs produce byte-identical state fingerprints.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .state import EndpointState

SUPPORTED_OPS = {
    "noop",
    "install_package",
    "remove_package",
    "set_registry",
    "delete_registry",
    "set_service",
    "delete_file",
    "create_file",
    "install_patch",
    "set_flag",
    "set_health",
    "set_reboot_pending",
}


class RemediationOpError(ValueError):
    pass


def validate_ops(ops: List[Dict[str, Any]]) -> None:
    for op in ops:
        name = op.get("op")
        if name not in SUPPORTED_OPS:
            raise RemediationOpError(f"unsupported remediation op: {name!r}")


def apply_ops(state: EndpointState, ops: List[Dict[str, Any]]) -> EndpointState:
    """Mutates and returns `state`.  Callers that need isolation clone first."""
    validate_ops(ops)
    for op in ops:
        _apply_one(state, op)
    return state


def _apply_one(state: EndpointState, op: Dict[str, Any]) -> None:
    name = op["op"]

    if name == "noop":
        return

    if name == "install_package":
        pkg = op["package"]
        versions = state.packages.setdefault(pkg, [])
        if op.get("remove_old", False):
            versions.clear()
        if op["version"] not in versions:
            versions.append(op["version"])
        versions.sort()
        return

    if name == "remove_package":
        pkg = op["package"]
        versions = state.packages.get(pkg)
        if versions is None:
            return
        version = op.get("version")
        if version is None:
            state.packages.pop(pkg, None)
        elif version in versions:
            versions.remove(version)
        return

    if name == "set_registry":
        state.registry[op["path"]] = op["value"]
        return

    if name == "delete_registry":
        state.registry.pop(op["path"], None)
        return

    if name == "set_service":
        svc = state.services.setdefault(op["service"], {"status": "stopped", "startup_type": "manual"})
        if "status" in op:
            svc["status"] = op["status"]
        if "startup_type" in op:
            svc["startup_type"] = op["startup_type"]
        return

    if name == "delete_file":
        state.files[op["path"]] = {"exists": False, "version": None}
        return

    if name == "create_file":
        state.files[op["path"]] = {"exists": True, "version": op.get("version")}
        return

    if name == "install_patch":
        kb = op["kb"]
        if op.get("requires_reboot", False):
            state.patches[kb] = {"installed": False, "staged": True}
            state.reboot_pending = True
        else:
            state.patches[kb] = {"installed": True, "staged": False}
        return

    if name == "set_flag":
        state.security_flags[op["flag"]] = op["value"]
        return

    if name == "set_health":
        state.health_checks[op["check"]] = bool(op["value"])
        return

    if name == "set_reboot_pending":
        state.reboot_pending = bool(op["value"])
        return

    raise RemediationOpError(f"unhandled op {name!r}")
