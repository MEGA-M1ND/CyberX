"""Ground truth, derived from the latent world.

The oracle sees everything: every device (including ones no collector could
reach), every snapshot, the real reboot state.  It therefore never abstains -
`TruthLabel` has no INSUFFICIENT_EVIDENCE member.  Whether the *observer* had
enough evidence is a question about the collector, not about the endpoint, and
v2 keeps those separate.  (v1 conflated them.)

Resolution order, stated as a rule rather than buried in the code:

  1. Is the vulnerable condition present on any targeted device, now or after
     the next restart?  If so the outcome is a failure of some degree, and the
     degree depends on how much of the population and how much of a composite
     predicate is still affected.  Security dominates: a still-vulnerable box is
     not "remediated with a caveat".
  2. Otherwise, did the remediation create a new exposure?
  3. Otherwise, did it break something that had to keep working?
  4. Otherwise, did it actually reach every targeted device?
  5. Otherwise it succeeded.

This function is not imported by, and shares no helper with, any verifier.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from ..vocab import TruthLabel
from ..world.predicates import evaluate, top_level_components
from ..world.risk_library import STANDING_RISKS
from ..world.state import LatentDevice, LatentWorld, project_reboot


@dataclass
class Truth:
    label: str
    rationale: str
    detail: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"label": self.label, "rationale": self.rationale, "detail": self.detail}


def _vulnerable_now(device: LatentDevice, predicate: Dict[str, Any]) -> bool:
    return evaluate(predicate, device.current)


def _vulnerable_after_restart(device: LatentDevice, predicate: Dict[str, Any]) -> bool:
    return evaluate(predicate, project_reboot(device.current))


def derive_truth(world: LatentWorld) -> Truth:
    predicate = world.vulnerability_predicate

    # Every targeted device counts, including devices no collector can see.
    targeted = [world.device(did) for did in world.targeted_device_ids]

    now = {d.device_id: _vulnerable_now(d, predicate) for d in targeted}
    later = {d.device_id: _vulnerable_after_restart(d, predicate) for d in targeted}
    affected = [d.device_id for d in targeted if now[d.device_id] or later[d.device_id]]

    detail: Dict[str, Any] = {
        "targeted_devices": len(targeted),
        "vulnerable_now": sorted(k for k, v in now.items() if v),
        "vulnerable_after_restart": sorted(k for k, v in later.items() if v),
        "reboot_performed": world.reboot_performed,
    }

    if affected:
        if len(affected) < len(targeted):
            return Truth(TruthLabel.PARTIALLY_REMEDIATED.value,
                         f"{len(affected)} of {len(targeted)} targeted devices remain vulnerable",
                         detail)

        first = targeted[0]
        parts = top_level_components(predicate)
        if len(parts) > 1:
            outstanding = [p.get("id", p.get("op")) for p in parts
                           if evaluate(p, first.current) or evaluate(p, project_reboot(first.current))]
            detail["composite_parts"] = len(parts)
            detail["outstanding_parts"] = outstanding
            if 0 < len(outstanding) < len(parts):
                return Truth(TruthLabel.PARTIALLY_REMEDIATED.value,
                             "composite mitigation only partly applied: " + ", ".join(outstanding),
                             detail)

        if not now[first.device_id] and later[first.device_id]:
            return Truth(TruthLabel.REMEDIATION_FAILED.value,
                         "the vulnerable condition returns at the next restart", detail)
        if now[first.device_id] and not later[first.device_id]:
            return Truth(TruthLabel.PARTIALLY_REMEDIATED.value,
                         "remediation is staged only; the device stays vulnerable until it restarts",
                         detail)
        return Truth(TruthLabel.REMEDIATION_FAILED.value,
                     "the vulnerable condition is still present", detail)

    exposures: List[str] = []
    for device in targeted:
        for risk in STANDING_RISKS:
            if evaluate(risk, device.current):
                exposures.append(f"{device.device_id}:{risk['id']}")
    if exposures:
        detail["new_exposures"] = exposures
        return Truth(TruthLabel.NEW_SECURITY_RISK.value,
                     "target condition resolved but a new exposure was created: " + exposures[0],
                     detail)

    broken: List[str] = []
    for device in targeted:
        for check in world.required_health_checks:
            if device.current.application_health.get(check) is False:
                broken.append(f"{device.device_id}:{check}")
    if broken:
        detail["failing_health_checks"] = broken
        return Truth(TruthLabel.REGRESSION_INTRODUCED.value,
                     "target condition resolved but required functionality broke: " + broken[0],
                     detail)

    reached = [d for d in targeted if d.enumerable]
    if len(reached) < len(targeted):
        detail["unreached_devices"] = sorted(d.device_id for d in targeted if not d.enumerable)
        return Truth(TruthLabel.PARTIALLY_REMEDIATED.value,
                     f"only {len(reached)} of {len(targeted)} targeted devices were reached", detail)

    return Truth(TruthLabel.VERIFIED_REMEDIATED.value,
                 "clean now, clean after restart, no new exposure, no regression, full rollout", detail)
