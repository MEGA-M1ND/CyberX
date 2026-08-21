"""rv3 - Remediation Verification v3.

Real Windows collector blindness and cross-collector evidence recovery.

v2 established that scope-aware verification is a complete defence against
collection gaps a collector *declares*, and no defence at all against gaps it
does not.  All 19 of v2's residual unsafe escapes were of the second kind.  v3
asks whether real Windows inventory mechanisms produce that second kind of gap,
how often, and whether a second collection channel recovers it.

Two execution modes, and the difference between them is the whole point:

    DRY_RUN   Derives, from each collector's declared scope contract and each
              fixture's decisive-evidence coordinates, which facts that collector
              *would* silently miss.  This is a deduction from documented
              behaviour, not a measurement.  Every output is labelled PREDICTED.

    REAL_LAB  Runs the read-only collectors against a disposable Windows VM and
              measures what they actually return.  Requires both
              ALLOW_WINDOWS_FIXTURE_SETUP=1 and ALLOW_REAL_WINDOWS_LAB=1, an
              interactive confirmation, and a preflight identity check.  Without
              all of those it fails closed.

Nothing in this package may state a measured result while running in DRY_RUN.
"""

__version__ = "3.0.0"
EXPERIMENT_ID = "remediation-verification-v3"
