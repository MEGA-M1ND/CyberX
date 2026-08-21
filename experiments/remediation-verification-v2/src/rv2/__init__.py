"""rv2 - Remediation Verification v2.

Evidence completeness, adversarial collector blindness, and fail-closed
verification.  Simulation only; stdlib only.

Layering is load-bearing and enforced by tests/test_layering.py:

    world/    latent endpoint reality        - oracle + collector only
    oracle/   ground truth from the latent world
    collect/  turns latent reality into a lossy ObservationPackage
    obs/      the serialised package + manifest, and an observational
              predicate evaluator
    verifiers/ see obs/ and nothing else

No verifier module may import world, oracle, collect, bench, or metrics.
"""

__version__ = "2.0.0"
EXPERIMENT_ID = "remediation-verification-v2"
