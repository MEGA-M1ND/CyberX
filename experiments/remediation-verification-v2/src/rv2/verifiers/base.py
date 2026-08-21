"""Verifier interface.

A verifier receives an ObservationPackage and, for the active arm, a bounded
request channel.  It receives no latent state, no truth label, no scenario
family, and no scorer.  `tests/test_layering.py` enforces that by inspecting
imports rather than trusting the convention.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from ..obs.package import ObservationPackage


class EvidenceRequestChannel(Protocol):
    """The narrow interface Arm E is allowed to use."""

    def request_evidence(self, evidence_type: str, device_id: str) -> Any: ...

    def build_package(self) -> ObservationPackage: ...


@dataclass
class Decision:
    verdict: str
    confidence: float
    reason_codes: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    arm: str = ""
    latency_units: float = 0.0
    evidence_requests: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arm": self.arm,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reason_codes": list(self.reason_codes),
            "evidence": self.evidence,
            "latency_units": self.latency_units,
            "evidence_requests": list(self.evidence_requests),
        }


class Verifier(ABC):
    arm: str = "UNSET"
    version: str = "2.0.0"
    needs_manifest: bool = False

    @abstractmethod
    def decide(self, package: ObservationPackage,
               channel: Optional[EvidenceRequestChannel] = None) -> Decision: ...

    def run(self, package: ObservationPackage,
            channel: Optional[EvidenceRequestChannel] = None) -> Decision:
        started = time.perf_counter()
        decision = self.decide(package, channel)
        decision.arm = self.arm
        # A latency *proxy*: observation reads plus evidence requests, which is
        # what would cost real time on a real fleet.  Wall-clock in a simulator
        # measures the simulator.
        decision.latency_units = round(
            len(package.items) + 10.0 * len(decision.evidence_requests), 3)
        decision.evidence.setdefault("wall_clock_ms", round((time.perf_counter() - started) * 1000, 4))
        return decision
