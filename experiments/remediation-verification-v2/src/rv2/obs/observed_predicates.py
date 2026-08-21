"""Observation-side predicate evaluation.

Three-valued, and deliberately a separate implementation from
`rv2/world/predicates.py`.  The latent evaluator answers "is this true?"; this
one answers the harder question "can I justify an answer from what I was
actually given?", which needs provenance, scope, freshness, and disagreement.

Two entry points, matching the two views of a package:

    evaluate_flat    what a scope-unaware consumer can do: read the merged
                     inventory, and treat an absent item - but nothing else - as
                     unresolved.  A field that was silently never queried reads
                     as "not present on the device".

    evaluate_scoped  what a scope-aware consumer can do: refuse to answer unless
                     the query that would have found the fact was actually run,
                     came back fresh, and no second collector disputes it.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ..vocab import EvidenceType, FailureReason
from .package import FULL_SCOPE, ObservationPackage

E = EvidenceType


class ObsValue(str, enum.Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNRESOLVED = "UNRESOLVED"


@dataclass
class Blocker:
    kind: str
    evidence_type: str
    device_id: str
    detail: str = ""

    def key(self) -> str:
        return f"{self.kind}:{self.evidence_type}:{self.device_id}"

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "evidence_type": self.evidence_type,
                "device_id": self.device_id, "detail": self.detail}


@dataclass
class ObsResult:
    value: ObsValue
    blockers: List[Blocker] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return self.value is not ObsValue.UNRESOLVED


# --------------------------------------------------------------------------- #
# Which evidence type and which scope partitions a leaf depends on.
# --------------------------------------------------------------------------- #
def evidence_type_for(op: str) -> str:
    if op.startswith("package_"):
        return E.PACKAGE_INVENTORY.value
    if op.startswith("registry_"):
        return E.REGISTRY_STATE.value
    if op.startswith("service_"):
        return E.SERVICE_STATE.value
    if op.startswith("file_"):
        return E.FILE_STATE.value
    if op.startswith("patch_"):
        return E.PATCH_STATE.value
    if op.startswith("posture_flag_"):
        return E.SECURITY_POSTURE.value
    raise ValueError(f"unknown observed op {op!r}")


def _registry_root(path: str) -> str:
    """Local copy; the world package has its own.  Kept separate on purpose."""
    best = ""
    for root in FULL_SCOPE[E.REGISTRY_STATE.value]:
        if path.startswith(root) and len(root) > len(best):
            best = root
    return best or path.split("\\", 1)[0]


def _filesystem_root(path: str) -> str:
    best = ""
    for root in FULL_SCOPE[E.FILE_STATE.value]:
        if path.startswith(root) and len(root) > len(best):
            best = root
    return best or path[:3]


def required_scopes_for(node: Dict[str, Any]) -> Set[str]:
    """Partitions that must have been queried before this leaf can be trusted.

    Path-addressed facts pin a single partition.  Name-addressed facts do not:
    a vulnerable copy of a package can sit in either install scope, and a service
    can have any startup type, so those leaves need the whole surface.  That
    asymmetry is why a narrowed inventory is so much more dangerous than a
    narrowed file query.
    """
    op = node["op"]
    etype = evidence_type_for(op)
    if op.startswith("registry_"):
        return {_registry_root(node["path"])}
    if op.startswith("file_"):
        return {_filesystem_root(node["path"])}
    return set(FULL_SCOPE[etype])


def field_key_for(node: Dict[str, Any]) -> str:
    op = node["op"]
    if op.startswith("package_"):
        return f"package:{node['package']}"
    if op.startswith("registry_"):
        return f"registry:{node['path']}"
    if op.startswith("service_"):
        return f"service:{node['service']}"
    if op.startswith("file_"):
        return f"file:{node['path']}"
    if op.startswith("patch_"):
        return f"patch:{node['kb']}"
    return f"posture:{node['flag']}"


# --------------------------------------------------------------------------- #
# Leaf reading over an item's value payload.
# --------------------------------------------------------------------------- #
def _version_below(candidate: str, fixed: str) -> bool:
    def parse(v: str) -> List[int]:
        out: List[int] = []
        for part in str(v).split("."):
            digits = ""
            for ch in part:
                if not ch.isdigit():
                    break
                digits += ch
            out.append(int(digits) if digits else -1)
        return out

    a, b = parse(candidate), parse(fixed)
    n = max(len(a), len(b))
    return (a + [0] * (n - len(a))) < (b + [0] * (n - len(b)))


def read_leaf(node: Dict[str, Any], value: Dict[str, Any]) -> bool:
    op = node["op"]

    if op.startswith("package_"):
        matches = [p for p in value.get("packages", []) if p["name"] == node["package"]]
        if op == "package_version_below":
            return any(_version_below(p["version"], node["fixed_version"]) for p in matches)
        if op == "package_present":
            return any(p["version"] == node["version"] for p in matches)
        return not any(p["version"] == node["version"] for p in matches)

    if op.startswith("registry_"):
        registry = value.get("registry", {})
        present = node["path"] in registry
        if op == "registry_key_present":
            return present
        if op == "registry_equals":
            return present and registry[node["path"]] == node["value"]
        return (not present) or registry[node["path"]] != node["value"]

    if op.startswith("service_"):
        svc = value.get("services", {}).get(node["service"])
        if svc is None:
            return False
        if op == "service_running":
            return svc.get("status") == "running"
        if op == "service_stopped":
            return svc.get("status") == "stopped"
        return svc.get("startup_type") == node["startup_type"]

    if op.startswith("file_"):
        entry = value.get("files", {}).get(node["path"])
        if op == "file_present":
            return bool(entry and entry.get("exists"))
        if op == "file_absent":
            return not (entry and entry.get("exists"))
        if not entry or not entry.get("exists") or entry.get("version") is None:
            return False
        return _version_below(entry["version"], node["fixed_version"])

    if op.startswith("patch_"):
        patch = value.get("patches", {}).get(node["kb"], {"installed": False, "staged": False})
        if op == "patch_installed":
            return bool(patch.get("installed"))
        if op == "patch_staged":
            return bool(patch.get("staged"))
        return not patch.get("installed")

    if op == "posture_flag_true":
        return bool(value.get("security_posture", {}).get(node["flag"]))
    if op == "posture_flag_equals":
        return value.get("security_posture", {}).get(node["flag"]) == node["value"]

    raise ValueError(f"unhandled observed op {op!r}")


# --------------------------------------------------------------------------- #
# Combinators
# --------------------------------------------------------------------------- #
def _combine(op: str, results: List[ObsResult]) -> ObsResult:
    blockers = [b for r in results for b in r.blockers]
    if op == "any_of":
        if any(r.value is ObsValue.TRUE for r in results):
            return ObsResult(ObsValue.TRUE)
        if any(r.value is ObsValue.UNRESOLVED for r in results):
            return ObsResult(ObsValue.UNRESOLVED, blockers)
        return ObsResult(ObsValue.FALSE)
    if op == "all_of":
        if any(r.value is ObsValue.FALSE for r in results):
            return ObsResult(ObsValue.FALSE)
        if any(r.value is ObsValue.UNRESOLVED for r in results):
            return ObsResult(ObsValue.UNRESOLVED, blockers)
        return ObsResult(ObsValue.TRUE)
    raise ValueError(op)


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def evaluate_flat(node: Dict[str, Any], package: ObservationPackage, device_id: str) -> ObsResult:
    op = node.get("op")
    if op in ("any_of", "all_of"):
        return _combine(op, [evaluate_flat(c, package, device_id) for c in node["operands"]])
    if op == "not":
        inner = evaluate_flat(node["operand"], package, device_id)
        if inner.value is ObsValue.UNRESOLVED:
            return inner
        return ObsResult(ObsValue.FALSE if inner.value is ObsValue.TRUE else ObsValue.TRUE)

    etype = evidence_type_for(op)
    item = package.latest_item(etype, device_id)
    if item is None:
        return ObsResult(ObsValue.UNRESOLVED,
                         [Blocker("ITEM_MISSING", etype, device_id, "no evidence item returned")])
    return ObsResult(ObsValue.TRUE if read_leaf(node, item.value) else ObsValue.FALSE)


def evaluate_scoped(node: Dict[str, Any], package: ObservationPackage, device_id: str) -> ObsResult:
    op = node.get("op")
    if op in ("any_of", "all_of"):
        return _combine(op, [evaluate_scoped(c, package, device_id) for c in node["operands"]])
    if op == "not":
        inner = evaluate_scoped(node["operand"], package, device_id)
        if inner.value is ObsValue.UNRESOLVED:
            return inner
        return ObsResult(ObsValue.FALSE if inner.value is ObsValue.TRUE else ObsValue.TRUE)

    etype = evidence_type_for(op)
    manifest = package.manifest
    if manifest is None:
        raise RuntimeError("evaluate_scoped requires a collection manifest")

    if device_id not in manifest.devices_observed:
        return ObsResult(ObsValue.UNRESOLVED, [Blocker(
            FailureReason.DEVICE_NOT_ENUMERATED.value, etype, device_id,
            "device was in the targeted group but never reported")])

    candidates = package.items_for(etype, device_id)
    if not candidates:
        reason = _failure_reason(manifest, etype, device_id) or "ITEM_MISSING"
        return ObsResult(ObsValue.UNRESOLVED,
                         [Blocker(reason, etype, device_id, "requested evidence did not come back")])

    needed = required_scopes_for(node)
    fkey = field_key_for(node)

    for contradiction in manifest.contradictions:
        if (contradiction.evidence_type == etype and contradiction.device_id == device_id
                and contradiction.field_key == fkey):
            return ObsResult(ObsValue.UNRESOLVED, [Blocker(
                FailureReason.CONTRADICTED.value, etype, device_id,
                f"{fkey} disputed by {', '.join(contradiction.collectors)}")])

    reference = _freshness_reference(manifest)
    usable = []
    stale_blockers: List[Blocker] = []
    scope_blockers: List[Blocker] = []
    for item in sorted(candidates, key=lambda i: (i.collected_at, i.evidence_id)):
        covered = set(manifest.covered_scope_keys.get(item.evidence_id, []))
        missing_scope = needed - covered
        if missing_scope:
            scope_blockers.append(Blocker(
                FailureReason.SCOPE_NARROWED.value, etype, device_id,
                f"{fkey} could hide in un-queried scope(s): {sorted(missing_scope)}"))
            continue
        if item.collected_at < reference:
            stale_blockers.append(Blocker(
                FailureReason.STALE.value, etype, device_id,
                f"collected at t={item.collected_at}, before the reference event at t={reference}"))
            continue
        usable.append(item)

    if not usable:
        return ObsResult(ObsValue.UNRESOLVED, scope_blockers + stale_blockers)

    item = usable[-1]
    return ObsResult(ObsValue.TRUE if read_leaf(node, item.value) else ObsValue.FALSE)


def _failure_reason(manifest, etype: str, device_id: str) -> Optional[str]:
    for failure in list(manifest.failed) + list(manifest.unsupported):
        if failure.evidence_type == etype and failure.device_id == device_id:
            return failure.reason
    return None


def _freshness_reference(manifest) -> int:
    """Evidence must post-date the last event that could have changed the answer."""
    reference = manifest.remediation_completed_at
    if manifest.reboot_performed_at is not None:
        reference = max(reference, manifest.reboot_performed_at)
    return reference
