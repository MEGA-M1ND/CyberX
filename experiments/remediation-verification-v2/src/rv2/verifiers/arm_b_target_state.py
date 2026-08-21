"""Arm B - TARGET_STATE.

Did the change the remediation set out to make actually show up?  This is the
configuration-baseline check that device-management platforms already ship.
Deliberately not strawmanned: it ignores exit codes, checks every device it can
see, and declines when an assertion's evidence never came back at all.

What it does not do, by definition of the arm, is ask the separate question of
whether the endpoint is still vulnerable.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..obs.observed_predicates import ObsValue, evaluate_flat
from ..obs.package import ObservationPackage
from ..vocab import Verdict
from .base import Decision, EvidenceRequestChannel, Verifier


class TargetStateVerifier(Verifier):
    arm = "B_TARGET_STATE"

    def decide(self, package: ObservationPackage,
               channel: Optional[EvidenceRequestChannel] = None) -> Decision:
        assertions = package.target_state_assertions
        devices = package.device_ids()
        evidence: Dict[str, Any] = {"devices_seen": len(devices), "assertions": len(assertions)}

        if not assertions or not devices:
            return Decision(Verdict.INSUFFICIENT_EVIDENCE.value, 0.5,
                            ["NO_TARGET_STATE_OBSERVABLE"], evidence)

        satisfied: List[str] = []
        unsatisfied: List[str] = []
        unresolved: List[str] = []
        for device_id in devices:
            for node in assertions:
                label = f"{device_id}:{node.get('id', node.get('op'))}"
                result = evaluate_flat(node, package, device_id)
                if result.value is ObsValue.UNRESOLVED:
                    unresolved.append(label)
                elif result.value is ObsValue.TRUE:
                    satisfied.append(label)
                else:
                    unsatisfied.append(label)

        evidence.update({"satisfied": len(satisfied), "unsatisfied": len(unsatisfied),
                         "unresolved": len(unresolved), "unsatisfied_labels": unsatisfied[:8]})

        if unresolved:
            return Decision(Verdict.INSUFFICIENT_EVIDENCE.value, 0.6,
                            ["TARGET_STATE_EVIDENCE_ABSENT"], evidence)
        if unsatisfied and satisfied:
            return Decision(Verdict.PARTIALLY_REMEDIATED.value, 0.75,
                            ["TARGET_STATE_PARTIALLY_APPLIED"], evidence)
        if unsatisfied:
            return Decision(Verdict.REMEDIATION_FAILED.value, 0.9,
                            ["TARGET_STATE_NOT_APPLIED"], evidence)
        return Decision(Verdict.VERIFIED_REMEDIATED.value, 0.85,
                        ["TARGET_STATE_APPLIED"], evidence)
