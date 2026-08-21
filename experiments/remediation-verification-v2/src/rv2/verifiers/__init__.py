"""Verifier arms.

These modules import from `rv2.obs` and `rv2.vocab` and nothing else in the
project.  No latent world, no oracle, no collector, no benchmark labels, no
metrics.  Enforced by tests/test_layering.py.
"""
from .arm_a_status_only import StatusOnlyVerifier
from .arm_b_target_state import TargetStateVerifier
from .arm_c_scope_unaware import ScopeUnawareIndependentVerifier
from .arm_d_scope_aware import ScopeAwareFailClosedVerifier
from .arm_e_active import ActiveEvidenceVerifier
from .base import Decision, Verifier

# Arms A, B and C consume the flat view: merged rows, no collection manifest.
FLAT_VIEW_ARMS = {"A_STATUS_ONLY", "B_TARGET_STATE", "C_SCOPE_UNAWARE_INDEPENDENT"}
ACTIVE_ARMS = {"E_ACTIVE_EVIDENCE"}


def build_arms():
    return [StatusOnlyVerifier(), TargetStateVerifier(), ScopeUnawareIndependentVerifier(),
            ScopeAwareFailClosedVerifier(), ActiveEvidenceVerifier()]


__all__ = ["Verifier", "Decision", "StatusOnlyVerifier", "TargetStateVerifier",
           "ScopeUnawareIndependentVerifier", "ScopeAwareFailClosedVerifier",
           "ActiveEvidenceVerifier", "build_arms", "FLAT_VIEW_ARMS", "ACTIVE_ARMS"]
