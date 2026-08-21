"""Arm E - ACTIVE_EVIDENCE_VERIFIER.

Arm D's problem is that abstaining is safe but unhelpful.  Arm E starts from the
identical observation and, when D would refuse for want of evidence, spends a
small, hard-capped budget asking the collector for the specific things that are
blocking it - then re-decides under exactly the same fail-closed rules.

The budget is three requests.  It is not a retry loop: each request names one
(evidence type, device) pair drawn from the current blocking set, chosen by
which gate it blocks.  Requests that cannot help - a denied ACL, an unsupported
platform - come back refused, and the arm abstains rather than lowering the bar.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..obs.observed_predicates import Blocker
from ..obs.package import ObservationPackage
from ..vocab import Verdict
from .arm_d_scope_aware import GATE_PRIORITY, ScopedAnalysis, analyse
from .base import Decision, EvidenceRequestChannel, Verifier

MAX_REQUESTS = 3
ALL_TYPES = "*"


def rank_blockers(blockers: List[Tuple[str, Blocker]]) -> List[Tuple[str, str, str]]:
    """(gate, evidence_type, device_id) worth asking about, most valuable first.

    Ordered by which gate the blocker holds shut, then by how many separate
    blockers a single request would clear.
    """
    counts: Dict[Tuple[str, str, str], int] = {}
    for gate, blocker in blockers:
        etype = blocker.evidence_type
        device = blocker.device_id
        if blocker.kind in ("DEVICE_NOT_ENUMERATED", "GROUP_SCOPE_INCOMPLETE") and device != "*":
            etype = ALL_TYPES
        counts[(gate, etype, device)] = counts.get((gate, etype, device), 0) + 1

    def sort_key(entry):
        (gate, etype, device), count = entry
        gate_rank = GATE_PRIORITY.index(gate) if gate in GATE_PRIORITY else len(GATE_PRIORITY)
        return (gate_rank, -count, etype, device)

    return [key for key, _ in sorted(counts.items(), key=sort_key)]


class ActiveEvidenceVerifier(Verifier):
    arm = "E_ACTIVE_EVIDENCE"
    needs_manifest = True

    def decide(self, package: ObservationPackage,
               channel: Optional[EvidenceRequestChannel] = None) -> Decision:
        analysis: ScopedAnalysis = analyse(package)
        requests: List[Dict[str, Any]] = []

        if channel is None or not analysis.abstained:
            return self._decision(analysis, requests, package, requested_any=False)

        channel.open_request_budget(MAX_REQUESTS)
        asked: set = set()

        for _ in range(MAX_REQUESTS):
            if not analysis.abstained:
                break
            candidates = [c for c in rank_blockers(analysis.blockers) if c[1:] not in asked]
            if not candidates:
                break
            gate, evidence_type, device_id = candidates[0]
            asked.add((evidence_type, device_id))

            blockers_before = len(analysis.blockers)
            verdict_before = analysis.verdict
            outcome = channel.request_evidence(evidence_type, device_id)
            if outcome.granted:
                package = channel.build_package()
                analysis = analyse(package)
            blockers_after = len(analysis.blockers)

            requests.append({
                "gate_targeted": gate,
                "evidence_type": evidence_type,
                "device_id": device_id,
                "granted": outcome.granted,
                "reason": outcome.reason,
                "repaired_cells": outcome.repaired_cells,
                "blockers_before": blockers_before,
                "blockers_after": blockers_after,
                # Measured, not asserted: did asking for this actually move the
                # decision?  Naming something in the blocking set is cheap; only
                # a request that shrinks the blocking set or settles the verdict
                # earned its cost.
                "decision_relevant": blockers_after < blockers_before
                                     or analysis.verdict != verdict_before,
            })

        return self._decision(analysis, requests, package, requested_any=bool(requests))

    def _decision(self, analysis: ScopedAnalysis, requests: List[Dict[str, Any]],
                  package: ObservationPackage, requested_any: bool) -> Decision:
        evidence = dict(analysis.evidence)
        evidence["evidence_requests_made"] = len(requests)
        evidence["evidence_requests_granted"] = sum(1 for r in requests if r["granted"])
        codes = list(analysis.reason_codes)
        if requested_any:
            codes.append("ADDITIONAL_EVIDENCE_REQUESTED")
            if not analysis.abstained:
                codes.append("RESOLVED_AFTER_ADDITIONAL_EVIDENCE")
        confidence = 0.9 if analysis.verdict != Verdict.INSUFFICIENT_EVIDENCE.value else 0.85
        decision = Decision(analysis.verdict, confidence, codes, evidence)
        decision.evidence_requests = requests
        return decision
