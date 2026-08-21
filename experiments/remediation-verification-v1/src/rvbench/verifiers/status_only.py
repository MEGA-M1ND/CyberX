"""Arm A - STATUS_ONLY.

The naive baseline this experiment exists to challenge: the remediation ran,
the tool said Succeeded, therefore the vulnerability is fixed.  It looks at
execution metadata and nothing else.
"""
from __future__ import annotations

from ..models import Verdict, VerifierOutput
from .base import Verifier, VerifierInput

SUCCESS_STATUSES = {"succeeded", "success", "compliant", "completed", "ok"}


class StatusOnlyVerifier(Verifier):
    arm = "STATUS_ONLY"
    version = "1.0.0"

    def verify(self, inp: VerifierInput) -> VerifierOutput:
        ex = inp.adapter.get_execution_result()
        exec_ok = ex.exit_code == 0
        status_ok = ex.execution_status.strip().lower() in SUCCESS_STATUSES
        deploy_ok = ex.deployment_status.strip().lower() in SUCCESS_STATUSES

        evidence = {
            "execution_exit_code": ex.exit_code,
            "execution_status": ex.execution_status,
            "deployment_status": ex.deployment_status,
            "devices_targeted": ex.devices_targeted,
            "devices_reported_success": ex.devices_reported_success,
        }

        if exec_ok and status_ok and deploy_ok:
            return VerifierOutput(
                verdict=Verdict.VERIFIED_REMEDIATED.value,
                confidence=0.95,
                reason_codes=["EXIT_CODE_ZERO", "DEPLOYMENT_REPORTED_SUCCESS"],
                evidence=evidence,
            )

        reasons = []
        if not exec_ok:
            reasons.append("NONZERO_EXIT_CODE")
        if not status_ok:
            reasons.append("EXECUTION_STATUS_NOT_SUCCESS")
        if not deploy_ok:
            reasons.append("DEPLOYMENT_STATUS_NOT_SUCCESS")
        return VerifierOutput(
            verdict=Verdict.REMEDIATION_FAILED.value,
            confidence=0.9,
            reason_codes=reasons,
            evidence=evidence,
        )
