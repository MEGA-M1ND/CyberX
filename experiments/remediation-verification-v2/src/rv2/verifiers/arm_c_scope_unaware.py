"""Arm C - SCOPE_UNAWARE_INDEPENDENT.

The v1 independent verifier, carried into v2 unchanged in spirit: it asks the
separate question "is this endpoint still vulnerable, now and after the next
restart, and did fixing it cost anything?" - and it answers from whatever
evidence happens to be in front of it.

It has no collection manifest.  So:
  * a partition that was never queried reads as "nothing there"
  * a timestamp has no reference point to be stale against
  * a merged inventory row hides that two collectors disagreed

It does fail closed when an evidence item is wholly absent, because that much is
visible without a manifest.  Everything subtler is not.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..obs.observed_predicates import ObsValue, evaluate_flat
from ..obs.package import ObservationPackage
from ..vocab import EvidenceType, Verdict
from .base import Decision, EvidenceRequestChannel, Verifier

E = EvidenceType


def _components(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(node["operands"]) if node.get("op") == "any_of" else [node]


def _project_reboot_view(package: ObservationPackage, device_id: str) -> Dict[str, Any]:
    """Non-destructive restart projection from observable signals only."""
    services = {}
    item = package.latest_item(E.SERVICE_STATE.value, device_id)
    if item:
        for name, svc in item.value.get("services", {}).items():
            projected = dict(svc)
            if svc.get("startup_type") == "automatic":
                projected["status"] = "running"
            elif svc.get("startup_type") == "disabled":
                projected["status"] = "stopped"
            services[name] = projected
    patches = {}
    item = package.latest_item(E.PATCH_STATE.value, device_id)
    if item:
        for kb, patch in item.value.get("patches", {}).items():
            projected = dict(patch)
            if patch.get("staged"):
                projected["installed"] = True
                projected["staged"] = False
            patches[kb] = projected
    return {"services": services, "patches": patches}


class ScopeUnawareIndependentVerifier(Verifier):
    arm = "C_SCOPE_UNAWARE_INDEPENDENT"

    def decide(self, package: ObservationPackage,
               channel: Optional[EvidenceRequestChannel] = None) -> Decision:
        devices = package.device_ids()
        predicate = package.vulnerability_predicate
        report = package.execution_report
        evidence: Dict[str, Any] = {
            "devices_seen": len(devices),
            "devices_targeted": report.get("devices_targeted"),
            "exit_code": report.get("exit_code"),
        }

        if not devices:
            return Decision(Verdict.INSUFFICIENT_EVIDENCE.value, 0.8,
                            ["NO_ENDPOINT_EVIDENCE"], evidence)

        vuln_now: Dict[str, bool] = {}
        vuln_later: Dict[str, bool] = {}
        unresolved: List[str] = []
        for device_id in devices:
            now = evaluate_flat(predicate, package, device_id)
            later = self._after_restart(predicate, package, device_id)
            if now.value is ObsValue.UNRESOLVED or later.value is ObsValue.UNRESOLVED:
                unresolved.append(device_id)
                continue
            vuln_now[device_id] = now.value is ObsValue.TRUE
            vuln_later[device_id] = later.value is ObsValue.TRUE

        if unresolved:
            evidence["unresolved_devices"] = unresolved[:8]
            return Decision(Verdict.INSUFFICIENT_EVIDENCE.value, 0.85,
                            ["VULNERABILITY_PREDICATE_UNRESOLVED"], evidence)

        evidence["vulnerable_now"] = sorted(d for d, v in vuln_now.items() if v)
        evidence["vulnerable_after_restart"] = sorted(d for d, v in vuln_later.items() if v)

        affected = [d for d in devices if vuln_now[d] or vuln_later[d]]
        duplicates = self._duplicate_installs(package, devices)
        evidence["duplicate_installs"] = duplicates[:8]

        if affected:
            reasons = ["VULNERABILITY_PREDICATE_STILL_TRUE"]
            if duplicates:
                reasons.append("VULNERABLE_DUPLICATE_INSTALL_PRESENT")
            if len(affected) < len(devices):
                return Decision(Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                                reasons + ["SUBSET_OF_GROUP_STILL_VULNERABLE"], evidence)
            parts = _components(predicate)
            if len(parts) > 1:
                outstanding = [p.get("id", p.get("op")) for p in parts
                               if evaluate_flat(p, package, devices[0]).value is ObsValue.TRUE
                               or self._after_restart(p, package, devices[0]).value is ObsValue.TRUE]
                evidence["outstanding_components"] = outstanding
                if 0 < len(outstanding) < len(parts):
                    return Decision(Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                                    reasons + ["COMPOSITE_PARTIALLY_REMEDIATED"], evidence)
            first = devices[0]
            if not vuln_now[first] and vuln_later[first]:
                return Decision(Verdict.REMEDIATION_FAILED.value, 0.93,
                                reasons + ["NOT_PERSISTENT_ACROSS_RESTART"], evidence)
            if vuln_now[first] and not vuln_later[first]:
                return Decision(Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                                reasons + ["STAGED_PENDING_RESTART"], evidence)
            return Decision(Verdict.REMEDIATION_FAILED.value, 0.95, reasons, evidence)

        risks = self._risks(package, devices)
        if risks:
            evidence["new_exposures"] = risks[:8]
            return Decision(Verdict.NEW_SECURITY_RISK.value, 0.9,
                            ["TARGET_CONDITION_RESOLVED", "NEW_EXPOSURE_DETECTED"], evidence)

        broken = self._broken_health(package, devices)
        if broken:
            evidence["failing_health_checks"] = broken[:8]
            return Decision(Verdict.REGRESSION_INTRODUCED.value, 0.88,
                            ["TARGET_CONDITION_RESOLVED", "REQUIRED_HEALTH_CHECK_FAILING"], evidence)

        targeted = int(report.get("devices_targeted") or len(devices))
        if len(devices) < targeted:
            return Decision(Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                            ["ROLLOUT_INCOMPLETE"], evidence)

        return Decision(Verdict.VERIFIED_REMEDIATED.value, 0.94,
                        ["VULNERABILITY_PREDICATE_FALSE", "PERSISTENT_ACROSS_RESTART",
                         "NO_REGRESSION_OBSERVED", "NO_NEW_EXPOSURE_OBSERVED",
                         "ROLLOUT_COMPLETE"], evidence)

    # ------------------------------------------------------------------ #
    def _after_restart(self, node, package: ObservationPackage, device_id: str):
        """Evaluate against a package whose service and patch rows are projected."""
        projected = _project_reboot_view(package, device_id)
        return evaluate_flat(node, _RestartView(package, device_id, projected), device_id)

    def _duplicate_installs(self, package: ObservationPackage, devices: List[str]) -> List[str]:
        out: List[str] = []
        for device_id in devices:
            item = package.latest_item(E.PACKAGE_INVENTORY.value, device_id)
            if not item:
                continue
            seen: Dict[str, set] = {}
            for pkg in item.value.get("packages", []):
                seen.setdefault(pkg["name"], set()).add(pkg["version"])
            for name, versions in sorted(seen.items()):
                if len(versions) > 1:
                    out.append(f"{device_id}:{name}={sorted(versions)}")
        return out

    def _risks(self, package: ObservationPackage, devices: List[str]) -> List[str]:
        out: List[str] = []
        for device_id in devices:
            for node in package.standing_risk_predicates:
                if evaluate_flat(node, package, device_id).value is ObsValue.TRUE:
                    out.append(f"{device_id}:{node['id']}")
        return out

    def _broken_health(self, package: ObservationPackage, devices: List[str]) -> List[str]:
        out: List[str] = []
        for device_id in devices:
            item = package.latest_item(E.APPLICATION_HEALTH.value, device_id)
            if not item:
                continue
            health = item.value.get("application_health", {})
            for check in package.required_health_checks:
                if health.get(check) is False:
                    out.append(f"{device_id}:{check}")
        return out


class _RestartView:
    """A read-only overlay presenting post-restart service and patch rows."""

    def __init__(self, package: ObservationPackage, device_id: str, projected: Dict[str, Any]) -> None:
        self._package = package
        self._device_id = device_id
        self._projected = projected

    def __getattr__(self, name):
        return getattr(self._package, name)

    def latest_item(self, evidence_type: str, device_id: str):
        item = self._package.latest_item(evidence_type, device_id)
        if item is None or device_id != self._device_id:
            return item
        if evidence_type == E.SERVICE_STATE.value:
            return _swap(item, {"services": self._projected["services"]})
        if evidence_type == E.PATCH_STATE.value:
            return _swap(item, {"patches": self._projected["patches"]})
        return item


def _swap(item, value):
    from dataclasses import replace
    return replace(item, value=value)
