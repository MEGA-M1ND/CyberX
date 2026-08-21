"""Declarative, three-valued predicate DSL.

Predicates are pure JSON, which means they can live in the *public* case file
without leaking anything about the outcome: they describe what "vulnerable"
means, not whether the endpoint still is.

Evaluation is three-valued.  When a predicate needs an evidence class that the
state view cannot speak about, the result is UNKNOWN, never False.  That is
what lets the verifier fail closed instead of fabricating safety.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from .models import EvidenceType, Tri
from .simulator.state import EndpointState, version_lt

# Which evidence class each leaf op consumes.
OP_EVIDENCE: Dict[str, EvidenceType] = {
    "package_version_below": EvidenceType.PACKAGE_STATE,
    "package_present": EvidenceType.PACKAGE_STATE,
    "package_absent": EvidenceType.PACKAGE_STATE,
    "package_duplicate_below": EvidenceType.PACKAGE_STATE,
    "registry_equals": EvidenceType.REGISTRY_STATE,
    "registry_not_equals": EvidenceType.REGISTRY_STATE,
    "service_startup_is": EvidenceType.SERVICE_STATE,
    "service_running": EvidenceType.SERVICE_STATE,
    "service_stopped": EvidenceType.SERVICE_STATE,
    "file_exists": EvidenceType.FILE_STATE,
    "file_absent": EvidenceType.FILE_STATE,
    "file_version_below": EvidenceType.FILE_STATE,
    "patch_missing": EvidenceType.PATCH_STATE,
    "patch_installed": EvidenceType.PATCH_STATE,
    "patch_staged": EvidenceType.PATCH_STATE,
    "flag_equals": EvidenceType.SECURITY_PREDICATE,
    "flag_true": EvidenceType.SECURITY_PREDICATE,
    "health_failing": EvidenceType.SMOKE_TEST,
    "health_passing": EvidenceType.SMOKE_TEST,
    "reboot_pending": EvidenceType.REBOOT_STATE,
    "always_false": EvidenceType.EXECUTION_STATUS,
}

COMBINATORS = {"any_of", "all_of", "not"}


class PredicateError(ValueError):
    pass


def required_evidence(node: Dict[str, Any]) -> Set[str]:
    """Every evidence class the predicate tree touches."""
    op = node.get("op")
    if op in ("any_of", "all_of"):
        out: Set[str] = set()
        for child in node.get("operands", []):
            out |= required_evidence(child)
        return out
    if op == "not":
        return required_evidence(node["operand"])
    if op not in OP_EVIDENCE:
        raise PredicateError(f"unknown predicate op: {op!r}")
    return {OP_EVIDENCE[op].value}


def components(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Top-level components of a composite vulnerability predicate.

    A vulnerability written as `any_of[a, b, c]` has three independently
    remediable components; anything else is a single component.  This is what
    makes PARTIALLY_REMEDIATED mechanically decidable.
    """
    if node.get("op") == "any_of":
        return list(node.get("operands", []))
    return [node]


def _tri(b: bool) -> Tri:
    return Tri.TRUE if b else Tri.FALSE


def evaluate(node: Dict[str, Any], state: EndpointState) -> Tri:
    op = node.get("op")

    if op == "any_of":
        results = [evaluate(c, state) for c in node.get("operands", [])]
        if any(r is Tri.TRUE for r in results):
            return Tri.TRUE
        if any(r is Tri.UNKNOWN for r in results):
            return Tri.UNKNOWN
        return Tri.FALSE

    if op == "all_of":
        results = [evaluate(c, state) for c in node.get("operands", [])]
        if any(r is Tri.FALSE for r in results):
            return Tri.FALSE
        if any(r is Tri.UNKNOWN for r in results):
            return Tri.UNKNOWN
        return Tri.TRUE

    if op == "not":
        r = evaluate(node["operand"], state)
        if r is Tri.UNKNOWN:
            return Tri.UNKNOWN
        return Tri.FALSE if r is Tri.TRUE else Tri.TRUE

    if op not in OP_EVIDENCE:
        raise PredicateError(f"unknown predicate op: {op!r}")

    # Fail closed: no evidence class -> UNKNOWN.
    if OP_EVIDENCE[op].value not in state.available:
        return Tri.UNKNOWN

    return _eval_leaf(op, node, state)


def _eval_leaf(op: str, node: Dict[str, Any], state: EndpointState) -> Tri:
    if op == "always_false":
        return Tri.FALSE

    if op in ("package_version_below", "package_present", "package_absent", "package_duplicate_below"):
        versions = state.packages.get(node["package"], [])
        if op == "package_version_below":
            return _tri(any(version_lt(v, node["fixed_version"]) for v in versions))
        if op == "package_present":
            return _tri(node["version"] in versions)
        if op == "package_absent":
            return _tri(node["version"] not in versions)
        # package_duplicate_below: more than one version installed AND one is vulnerable
        return _tri(len(versions) > 1 and any(version_lt(v, node["fixed_version"]) for v in versions))

    if op in ("registry_equals", "registry_not_equals"):
        present = node["path"] in state.registry
        value = state.registry.get(node["path"])
        if op == "registry_equals":
            return _tri(present and value == node["value"])
        # A missing key is *not* equal to the secure value -> still vulnerable.
        return _tri(not present or value != node["value"])

    if op in ("service_startup_is", "service_running", "service_stopped"):
        svc = state.services.get(node["service"])
        if svc is None:
            return Tri.FALSE
        if op == "service_startup_is":
            return _tri(svc.get("startup_type") == node["startup_type"])
        if op == "service_running":
            return _tri(svc.get("status") == "running")
        return _tri(svc.get("status") == "stopped")

    if op in ("file_exists", "file_absent", "file_version_below"):
        f = state.files.get(node["path"], {"exists": False, "version": None})
        if op == "file_exists":
            return _tri(bool(f.get("exists")))
        if op == "file_absent":
            return _tri(not f.get("exists"))
        if not f.get("exists") or f.get("version") is None:
            return Tri.FALSE
        return _tri(version_lt(f["version"], node["fixed_version"]))

    if op in ("patch_missing", "patch_installed", "patch_staged"):
        p = state.patches.get(node["kb"], {"installed": False, "staged": False})
        if op == "patch_missing":
            return _tri(not p.get("installed"))
        if op == "patch_staged":
            return _tri(bool(p.get("staged")))
        return _tri(bool(p.get("installed")))

    if op in ("flag_equals", "flag_true"):
        if op == "flag_true":
            return _tri(bool(state.security_flags.get(node["flag"])))
        return _tri(state.security_flags.get(node["flag"]) == node["value"])

    if op in ("health_failing", "health_passing"):
        val = state.health_checks.get(node["check"])
        if val is None:
            return Tri.UNKNOWN
        return _tri((not val) if op == "health_failing" else bool(val))

    if op == "reboot_pending":
        return _tri(state.reboot_pending)

    raise PredicateError(f"unhandled predicate op: {op!r}")
