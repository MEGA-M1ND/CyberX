"""Arm A - STATUS_ONLY.

The delivery tool said it worked, so it worked.  Carried forward unchanged from
v1 as the floor.
"""
from __future__ import annotations

from typing import Optional

from ..obs.package import ObservationPackage
from ..vocab import Verdict
from .base import Decision, EvidenceRequestChannel, Verifier

SUCCESS_WORDS = {"succeeded", "success", "compliant", "completed", "ok"}


class StatusOnlyVerifier(Verifier):
    arm = "A_STATUS_ONLY"

    def decide(self, package: ObservationPackage,
               channel: Optional[EvidenceRequestChannel] = None) -> Decision:
        report = package.execution_report
        exit_ok = report.get("exit_code") == 0
        exec_ok = str(report.get("execution_status", "")).lower() in SUCCESS_WORDS
        deploy_ok = str(report.get("deployment_status", "")).lower() in SUCCESS_WORDS
        evidence = {k: report.get(k) for k in
                    ("exit_code", "execution_status", "deployment_status",
                     "devices_targeted", "devices_reported_success")}

        if exit_ok and exec_ok and deploy_ok:
            return Decision(Verdict.VERIFIED_REMEDIATED.value, 0.95,
                            ["EXIT_CODE_ZERO", "DELIVERY_REPORTED_SUCCESS"], evidence)

        reasons = []
        if not exit_ok:
            reasons.append("NONZERO_EXIT_CODE")
        if not exec_ok:
            reasons.append("EXECUTION_STATUS_NOT_SUCCESS")
        if not deploy_ok:
            reasons.append("DEPLOYMENT_STATUS_NOT_SUCCESS")
        return Decision(Verdict.REMEDIATION_FAILED.value, 0.9, reasons, evidence)
