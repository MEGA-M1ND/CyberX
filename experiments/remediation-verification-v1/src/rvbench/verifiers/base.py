"""Verifier arm interface.

A verifier receives exactly two things: the PUBLIC case definition and an
EndpointAdapter.  It never receives the Scenario, the GroundTruth, or any
scorer object.  That is enforced by the signature and asserted by
tests/test_leakage.py.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..adapters.base import EndpointAdapter
from ..cases import PublicCase
from ..models import VerifierOutput


@dataclass(frozen=True)
class VerifierInput:
    case: PublicCase
    adapter: EndpointAdapter


class Verifier(ABC):
    arm: str = "UNSET"
    version: str = "1.0.0"

    @abstractmethod
    def verify(self, inp: VerifierInput) -> VerifierOutput: ...

    def run(self, inp: VerifierInput) -> VerifierOutput:
        start = time.perf_counter()
        out = self.verify(inp)
        out.arm = self.arm
        out.latency_ms = round((time.perf_counter() - start) * 1000.0, 4)
        return out
