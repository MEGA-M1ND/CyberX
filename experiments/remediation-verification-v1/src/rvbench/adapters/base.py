"""Adapter interface.

Everything above this line in the stack (verifiers, scorer, runner) talks only
to this interface, so a future WindowsLabAdapter / IntuneAdapter / SCCMAdapter /
JamfAdapter / WorkspaceOneAdapter can be dropped in without touching the
benchmark.  v1 ships exactly one concrete implementation: the simulator.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from ..models import ExecutionResult, Observation


class EndpointAdapter(ABC):
    """Read/act interface over one endpoint or one targeted device group.

    Contract notes:
      * Every inspect_* method returns an Observation whose `available` flag is
        False when the underlying evidence genuinely could not be collected.
        Implementations MUST NOT substitute an empty/default value for a failed
        collection - that is precisely the bug this experiment is measuring.
      * Methods are side-effect free except apply_remediation() and reboot().
    """

    @property
    @abstractmethod
    def device_count(self) -> int: ...

    @abstractmethod
    def apply_remediation(self) -> ExecutionResult: ...

    @abstractmethod
    def get_execution_result(self) -> ExecutionResult: ...

    @abstractmethod
    def inspect_packages(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def inspect_registry(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def inspect_services(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def inspect_files(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def inspect_patch_state(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def inspect_reboot_state(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def inspect_security_flags(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def reboot(self, device_index: int = 0) -> Observation:
        """Destructive.  Verifier arms in v1 do not call this; they use the
        non-destructive post-reboot projection instead."""

    @abstractmethod
    def run_smoke_tests(self, device_index: int = 0) -> Observation: ...

    @abstractmethod
    def evaluate_vulnerability_predicate(
        self, predicate: Dict[str, Any], device_index: int = 0, post_reboot: bool = False
    ) -> Observation:
        """Evaluate a predicate against the *observable* state only.

        This is not an oracle: it sees exactly what the collector saw, so blind
        spots and missing evidence propagate into the answer as UNKNOWN or, in
        the silent-blind-spot case, as a confidently wrong FALSE.
        """

    @abstractmethod
    def collect_evidence(self) -> Dict[str, Observation]:
        """One-shot bundle of every evidence class, fleet-wide."""
