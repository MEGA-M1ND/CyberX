"""Arm B - TARGET_STATE.

Checks one thing and one thing only: did the endpoint end up in the state the
remediation intended?  This is the "configuration baseline / compliance policy"
style of verification that most device-management stacks already offer.

Deliberately NOT strawmanned:
  * it ignores exit codes entirely, so a noisy-but-effective script does not
    fool it;
  * it evaluates its assertions on every enumerable device, not just device 0;
  * it fails closed when the evidence its assertions need is unavailable.

What it does not do - by definition of the arm - is ask the independent
question "is the endpoint still vulnerable?"
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import Tri, Verdict, VerifierOutput
from .base import Verifier, VerifierInput


class TargetStateVerifier(Verifier):
    arm = "TARGET_STATE"
    version = "1.0.0"

    def verify(self, inp: VerifierInput) -> VerifierOutput:
        assertions: List[Dict[str, Any]] = inp.case.target_state_assertions
        adapter = inp.adapter
        ex = adapter.get_execution_result()

        if not assertions:
            return VerifierOutput(
                verdict=Verdict.INSUFFICIENT_EVIDENCE.value,
                confidence=0.5,
                reason_codes=["NO_TARGET_STATE_DECLARED"],
                evidence={"execution_exit_code": ex.exit_code},
            )

        satisfied: List[str] = []
        unsatisfied: List[str] = []
        indeterminate: List[str] = []
        detail: List[Dict[str, Any]] = []

        for device_index in range(adapter.device_count):
            for node in assertions:
                aid = node.get("id", node.get("op", "assertion"))
                obs = adapter.evaluate_vulnerability_predicate(node, device_index=device_index)
                key = f"device{device_index}:{aid}"
                if not obs.available or obs.value == Tri.UNKNOWN.value:
                    indeterminate.append(key)
                elif obs.value == Tri.TRUE.value:
                    satisfied.append(key)
                else:
                    unsatisfied.append(key)
                detail.append({"assertion": key, "result": obs.value, "available": obs.available})

        evidence = {
            "execution_exit_code": ex.exit_code,
            "devices_enumerated": adapter.device_count,
            "assertions_satisfied": len(satisfied),
            "assertions_unsatisfied": len(unsatisfied),
            "assertions_indeterminate": len(indeterminate),
            "detail": detail,
        }

        if indeterminate:
            return VerifierOutput(
                verdict=Verdict.INSUFFICIENT_EVIDENCE.value,
                confidence=0.6,
                reason_codes=["TARGET_STATE_EVIDENCE_UNAVAILABLE"],
                evidence=evidence,
            )
        if unsatisfied and satisfied:
            return VerifierOutput(
                verdict=Verdict.PARTIALLY_REMEDIATED.value,
                confidence=0.75,
                reason_codes=["TARGET_STATE_PARTIALLY_APPLIED"],
                evidence=evidence,
            )
        if unsatisfied:
            return VerifierOutput(
                verdict=Verdict.REMEDIATION_FAILED.value,
                confidence=0.9,
                reason_codes=["TARGET_STATE_NOT_APPLIED"],
                evidence=evidence,
            )
        return VerifierOutput(
            verdict=Verdict.VERIFIED_REMEDIATED.value,
            confidence=0.85,
            reason_codes=["TARGET_STATE_APPLIED"],
            evidence=evidence,
        )
