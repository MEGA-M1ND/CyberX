"""SimulatedEndpointAdapter - the only adapter v1 needs.

Holds the *true* post-remediation state privately and exposes an observable
projection of it.  The projection can be lossy in two distinct ways:

  honest blindness  -> Observation.available = False   ("I could not collect this")
  silent blindness  -> Observation.available = True but the value is incomplete
                       ("here is the full inventory", when it is not)

Verifiers can defend against the first.  The second is the residual risk this
experiment is trying to size.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..cases import Environment, Scenario
from ..models import EvidenceType, ExecutionResult, Observation, Tri
from ..predicates import evaluate
from ..simulator.engine import apply_ops
from ..simulator.state import EndpointState, project_post_reboot
from .base import EndpointAdapter


class SimulatedEndpointAdapter(EndpointAdapter):
    def __init__(self, scenario: Scenario) -> None:
        self._scenario = scenario
        self._env: Environment = scenario.env()
        self._true_states: List[EndpointState] = scenario.endpoint_states()
        self._execution: ExecutionResult = scenario.execution()
        self._applied = False

    # ------------------------------------------------------------------ #
    # Actions
    # ------------------------------------------------------------------ #
    @property
    def device_count(self) -> int:
        return len(self._true_states)

    def apply_remediation(self) -> ExecutionResult:
        if self._applied:
            raise RuntimeError("remediation already applied for this adapter instance")
        for idx, state in enumerate(self._true_states):
            ops = self._scenario.remediation_ops[idx] if idx < len(self._scenario.remediation_ops) else []
            apply_ops(state, ops)
        self._applied = True
        return self._execution

    def get_execution_result(self) -> ExecutionResult:
        return self._execution

    def reboot(self, device_index: int = 0) -> Observation:
        st = self._true_states[device_index]
        self._true_states[device_index] = project_post_reboot(st, self._scenario.reboot_effects)
        return Observation(EvidenceType.REBOOT_STATE.value, True, {"rebooted": True})

    # ------------------------------------------------------------------ #
    # Harness-only accessors (NOT part of EndpointAdapter; the scorer uses
    # these, verifier arms are never handed the adapter's private state).
    # ------------------------------------------------------------------ #
    def _true_state(self, device_index: int = 0) -> EndpointState:
        return self._true_states[device_index]

    def _true_states_all(self) -> List[EndpointState]:
        return list(self._true_states)

    def _true_post_reboot(self, device_index: int = 0) -> EndpointState:
        return project_post_reboot(self._true_states[device_index], self._scenario.reboot_effects)

    # ------------------------------------------------------------------ #
    # Observation
    # ------------------------------------------------------------------ #
    def _observable(self, device_index: int = 0) -> EndpointState:
        """Build the lossy view a real collector would return."""
        st = self._true_states[device_index].clone()

        # Silent blindness: drop entries the collector never enumerates.
        for pkg, hidden in self._env.blind_spot_package_versions.items():
            if pkg in st.packages:
                st.packages[pkg] = [v for v in st.packages[pkg] if v not in hidden]
                if not st.packages[pkg]:
                    del st.packages[pkg]
        for path in self._env.blind_spot_registry_paths:
            st.registry.pop(path, None)
        for path in self._env.blind_spot_files:
            st.files.pop(path, None)
        for flag in self._env.blind_spot_flags:
            st.security_flags.pop(flag, None)

        # Honest blindness: whole evidence classes we admit we cannot read.
        st.available = {
            e for e in st.available if e not in set(self._env.unavailable_evidence)
        }
        return st

    def _observable_post_reboot(self, device_index: int = 0) -> EndpointState:
        """Post-reboot projection built from observable signals only.

        Non-destructive: it reasons from startup_type / staged-patch state, the
        same way an auditor would, rather than actually restarting the machine.
        """
        obs = self._observable(device_index)
        return project_post_reboot(obs, self._scenario.reboot_effects)

    def _obs(self, etype: EvidenceType, value: Any, device_index: int) -> Observation:
        if etype.value in self._env.unavailable_evidence:
            return Observation(
                etype.value,
                False,
                None,
                self._env.collector_note or f"{etype.value} could not be collected",
            )
        return Observation(etype.value, True, value)

    def inspect_packages(self, device_index: int = 0) -> Observation:
        return self._obs(EvidenceType.PACKAGE_STATE, self._observable(device_index).packages, device_index)

    def inspect_registry(self, device_index: int = 0) -> Observation:
        return self._obs(EvidenceType.REGISTRY_STATE, self._observable(device_index).registry, device_index)

    def inspect_services(self, device_index: int = 0) -> Observation:
        return self._obs(EvidenceType.SERVICE_STATE, self._observable(device_index).services, device_index)

    def inspect_files(self, device_index: int = 0) -> Observation:
        return self._obs(EvidenceType.FILE_STATE, self._observable(device_index).files, device_index)

    def inspect_patch_state(self, device_index: int = 0) -> Observation:
        return self._obs(EvidenceType.PATCH_STATE, self._observable(device_index).patches, device_index)

    def inspect_reboot_state(self, device_index: int = 0) -> Observation:
        st = self._observable(device_index)
        value = {
            "reboot_pending": st.reboot_pending,
            "services": {k: dict(v) for k, v in st.services.items()},
            "staged_patches": [k for k, v in st.patches.items() if v.get("staged")],
        }
        return self._obs(EvidenceType.REBOOT_STATE, value, device_index)

    def inspect_security_flags(self, device_index: int = 0) -> Observation:
        return self._obs(
            EvidenceType.SECURITY_PREDICATE, self._observable(device_index).security_flags, device_index
        )

    def run_smoke_tests(self, device_index: int = 0) -> Observation:
        return self._obs(EvidenceType.SMOKE_TEST, self._observable(device_index).health_checks, device_index)

    def evaluate_vulnerability_predicate(
        self, predicate: Dict[str, Any], device_index: int = 0, post_reboot: bool = False
    ) -> Observation:
        state = self._observable_post_reboot(device_index) if post_reboot else self._observable(device_index)
        result = evaluate(predicate, state)
        available = result is not Tri.UNKNOWN
        return Observation(
            EvidenceType.SECURITY_PREDICATE.value,
            available,
            result.value,
            "" if available else "predicate indeterminate: required evidence unavailable",
        )

    def collect_evidence(self) -> Dict[str, Observation]:
        bundle: Dict[str, Observation] = {
            EvidenceType.EXECUTION_STATUS.value: Observation(
                EvidenceType.EXECUTION_STATUS.value, True, self._execution.to_dict()
            )
        }
        per_device: List[Dict[str, Any]] = []
        for idx in range(self.device_count):
            per_device.append(
                {
                    "device_index": idx,
                    "packages": self.inspect_packages(idx).to_dict(),
                    "registry": self.inspect_registry(idx).to_dict(),
                    "services": self.inspect_services(idx).to_dict(),
                    "files": self.inspect_files(idx).to_dict(),
                    "patches": self.inspect_patch_state(idx).to_dict(),
                    "reboot": self.inspect_reboot_state(idx).to_dict(),
                    "flags": self.inspect_security_flags(idx).to_dict(),
                    "smoke": self.run_smoke_tests(idx).to_dict(),
                }
            )
        bundle["PER_DEVICE"] = Observation("PER_DEVICE", True, per_device)
        bundle[EvidenceType.FLEET_COVERAGE.value] = Observation(
            EvidenceType.FLEET_COVERAGE.value,
            EvidenceType.FLEET_COVERAGE.value not in self._env.unavailable_evidence,
            {"devices_enumerated": self.device_count, "devices_targeted": self._execution.devices_targeted},
        )
        return bundle

    def unavailable_evidence(self) -> List[str]:
        """Which evidence classes this collector openly cannot read."""
        return list(self._env.unavailable_evidence)
