from .base import Verifier, VerifierInput
from .independent import IndependentVerifier
from .status_only import StatusOnlyVerifier
from .target_state import TargetStateVerifier

ARMS = ["STATUS_ONLY", "TARGET_STATE", "INDEPENDENT_VERIFIER"]

def build_arms():
    return [StatusOnlyVerifier(), TargetStateVerifier(), IndependentVerifier()]

__all__ = ["Verifier", "VerifierInput", "StatusOnlyVerifier", "TargetStateVerifier",
           "IndependentVerifier", "ARMS", "build_arms"]
