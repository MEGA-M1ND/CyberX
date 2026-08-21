"""Arm C - INDEPENDENT_VERIFIER.

Answers a different question from Arm B.  Arm B asks "did my change land?".
Arm C asks "is this endpoint, right now and after the next reboot, still in the
vulnerable condition - and did fixing it cost anything?"

Signals combined:
  execution metadata
  + target-state validation
  + independent vulnerability predicate (evaluated on observed state)
  + persistence verification (non-destructive post-reboot projection)
  + regression checks (benign smoke tests)
  + duplicate / side-by-side installation scan
  + rollout completeness (devices enumerated vs devices targeted)
  + evidence sufficiency (fail closed)

It never sees the ground-truth label, the scenario, or the scorer.  It can and
does get things wrong when the collector is silently incomplete; that residual
is one of the findings of this experiment, not a bug.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from ..cases import STANDING_RISK_PREDICATES
from ..models import EvidenceType, Tri, Verdict, VerifierOutput
from ..predicates import components, required_evidence
from .base import Verifier, VerifierInput

E = EvidenceType


class IndependentVerifier(Verifier):
    arm = "INDEPENDENT_VERIFIER"
    version = "1.0.0"

    # ------------------------------------------------------------------ #
    def _required_evidence(self, case) -> Set[str]:
        req = set(required_evidence(case.vulnerability_predicate))
        req.add(E.EXECUTION_STATUS.value)
        req.add(E.REBOOT_STATE.value)
        req.add(E.SECURITY_PREDICATE.value)
        for node in case.target_state_assertions:
            req |= required_evidence(node)
        if case.required_health_checks:
            req.add(E.SMOKE_TEST.value)
        if case.fleet_size > 1:
            req.add(E.FLEET_COVERAGE.value)
        return req

    def _availability(self, adapter) -> Dict[str, bool]:
        """Probe the collector once per evidence class, across every device."""
        probes = {
            E.PACKAGE_STATE.value: adapter.inspect_packages,
            E.REGISTRY_STATE.value: adapter.inspect_registry,
            E.SERVICE_STATE.value: adapter.inspect_services,
            E.FILE_STATE.value: adapter.inspect_files,
            E.PATCH_STATE.value: adapter.inspect_patch_state,
            E.REBOOT_STATE.value: adapter.inspect_reboot_state,
            E.SECURITY_PREDICATE.value: adapter.inspect_security_flags,
            E.SMOKE_TEST.value: adapter.run_smoke_tests,
        }
        avail: Dict[str, bool] = {E.EXECUTION_STATUS.value: True}
        for name, fn in probes.items():
            avail[name] = all(fn(i).available for i in range(adapter.device_count))
        bundle = adapter.collect_evidence()
        fleet_obs = bundle.get(E.FLEET_COVERAGE.value)
        avail[E.FLEET_COVERAGE.value] = bool(fleet_obs and fleet_obs.available)
        return avail

    # ------------------------------------------------------------------ #
    def verify(self, inp: VerifierInput) -> VerifierOutput:
        case, adapter = inp.case, inp.adapter
        ex = adapter.get_execution_result()
        n = adapter.device_count

        evidence: Dict[str, Any] = {
            "execution_exit_code": ex.exit_code,
            "execution_status": ex.execution_status,
            "deployment_status": ex.deployment_status,
            "devices_enumerated": n,
            "devices_targeted": ex.devices_targeted,
        }

        # --- evidence sufficiency, fail closed --------------------------- #
        required = self._required_evidence(case)
        avail = self._availability(adapter)
        missing = sorted(e for e in required if not avail.get(e, False))
        evidence["required_evidence"] = sorted(required)
        evidence["missing_evidence"] = missing
        if missing:
            return VerifierOutput(
                verdict=Verdict.INSUFFICIENT_EVIDENCE.value,
                confidence=0.9,
                reason_codes=["REQUIRED_EVIDENCE_UNAVAILABLE"] + [f"MISSING_{m}" for m in missing],
                evidence=evidence,
            )

        # --- independent vulnerability predicate ------------------------- #
        pred = case.vulnerability_predicate
        vuln_now, vuln_after, indeterminate = [], [], False
        for i in range(n):
            a = adapter.evaluate_vulnerability_predicate(pred, device_index=i, post_reboot=False)
            b = adapter.evaluate_vulnerability_predicate(pred, device_index=i, post_reboot=True)
            if not a.available or not b.available:
                indeterminate = True
            vuln_now.append(a.value == Tri.TRUE.value)
            vuln_after.append(b.value == Tri.TRUE.value)
        evidence["vulnerable_now_per_device"] = vuln_now
        evidence["vulnerable_after_reboot_per_device"] = vuln_after

        if indeterminate:
            return VerifierOutput(
                verdict=Verdict.INSUFFICIENT_EVIDENCE.value,
                confidence=0.85,
                reason_codes=["VULNERABILITY_PREDICATE_INDETERMINATE"],
                evidence=evidence,
            )

        # --- target-state validation (supporting signal) ----------------- #
        ts_unsat = []
        for i in range(n):
            for node in case.target_state_assertions:
                obs = adapter.evaluate_vulnerability_predicate(node, device_index=i)
                if obs.value != Tri.TRUE.value:
                    ts_unsat.append(f"device{i}:{node.get('id', node.get('op'))}")
        evidence["target_state_unsatisfied"] = ts_unsat

        # --- duplicate / side-by-side scan ------------------------------- #
        duplicates: List[str] = []
        for i in range(n):
            pkgs = adapter.inspect_packages(i).value or {}
            for name, versions in pkgs.items():
                if len(versions) > 1:
                    duplicates.append(f"device{i}:{name}={sorted(versions)}")
        evidence["duplicate_installs"] = duplicates

        # --- rollout completeness ---------------------------------------- #
        rollout_incomplete = n < ex.devices_targeted
        evidence["rollout_complete"] = not rollout_incomplete

        # --- regression + standing new-risk library ---------------------- #
        failing_checks: List[str] = []
        for i in range(n):
            health = adapter.run_smoke_tests(i).value or {}
            for c in case.required_health_checks:
                if health.get(c) is False:
                    failing_checks.append(f"device{i}:{c}")
        evidence["failing_health_checks"] = failing_checks

        risks: List[str] = []
        for i in range(n):
            for node in STANDING_RISK_PREDICATES:
                obs = adapter.evaluate_vulnerability_predicate(node, device_index=i)
                if obs.value == Tri.TRUE.value:
                    risks.append(f"device{i}:{node['id']}")
        evidence["new_security_risks"] = risks

        # --- decision ----------------------------------------------------- #
        affected = [i for i in range(n) if vuln_now[i] or vuln_after[i]]

        if affected:
            reasons = ["VULNERABILITY_PREDICATE_STILL_TRUE"]
            if duplicates:
                reasons.append("VULNERABLE_DUPLICATE_INSTALL_PRESENT")
            if not ts_unsat:
                reasons.append("TARGET_STATE_APPLIED_BUT_STILL_VULNERABLE")

            if 0 < len(affected) < n:
                return VerifierOutput(
                    Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                    reasons + ["FLEET_SUBSET_STILL_VULNERABLE"], evidence)

            comps = components(pred)
            if len(comps) > 1:
                still = []
                for c in comps:
                    a = adapter.evaluate_vulnerability_predicate(c, 0, post_reboot=False)
                    b = adapter.evaluate_vulnerability_predicate(c, 0, post_reboot=True)
                    if Tri.TRUE.value in (a.value, b.value):
                        still.append(c.get("id", c.get("op")))
                evidence["vulnerable_components"] = still
                evidence["total_components"] = len(comps)
                if 0 < len(still) < len(comps):
                    return VerifierOutput(
                        Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                        reasons + ["COMPOSITE_PREDICATE_PARTIALLY_REMEDIATED"], evidence)

            if not vuln_now[0] and vuln_after[0]:
                return VerifierOutput(
                    Verdict.REMEDIATION_FAILED.value, 0.93,
                    reasons + ["REMEDIATION_NOT_PERSISTENT_ACROSS_REBOOT"], evidence)
            if vuln_now[0] and not vuln_after[0]:
                return VerifierOutput(
                    Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                    reasons + ["REMEDIATION_STAGED_PENDING_REBOOT"], evidence)
            return VerifierOutput(Verdict.REMEDIATION_FAILED.value, 0.96, reasons, evidence)

        if risks:
            return VerifierOutput(
                Verdict.NEW_SECURITY_RISK.value, 0.9,
                ["TARGET_CONDITION_RESOLVED", "NEW_UNSAFE_CONFIGURATION_DETECTED"], evidence)

        if failing_checks:
            return VerifierOutput(
                Verdict.REGRESSION_INTRODUCED.value, 0.88,
                ["TARGET_CONDITION_RESOLVED", "REQUIRED_SMOKE_TEST_FAILING"], evidence)

        if rollout_incomplete:
            return VerifierOutput(
                Verdict.PARTIALLY_REMEDIATED.value, 0.9,
                ["ROLLOUT_INCOMPLETE", "DEVICES_TARGETED_EXCEEDS_DEVICES_CONFIRMED"], evidence)

        reasons = ["VULNERABILITY_PREDICATE_FALSE", "PERSISTENT_ACROSS_REBOOT_PROJECTION",
                   "NO_REGRESSION_DETECTED", "NO_NEW_RISK_DETECTED", "ROLLOUT_COMPLETE"]
        if not ts_unsat:
            reasons.append("TARGET_STATE_APPLIED")
        return VerifierOutput(Verdict.VERIFIED_REMEDIATED.value, 0.94, reasons, evidence)
