# Experiment log

Chronological, append-only. Each entry records what was run, what came out, and what it
changed about our beliefs — including when the answer was "less than we hoped".

---

## 2026-08-21 — EXP-001 — Endpoint Remediation Verification Benchmark v1

**Hypothesis.** H1: treating `exit_code == 0` as remediation success produces a materially
higher false-safe rate than independently verifying post-remediation security state.
H2: independent verification materially reduces false-safe outcomes. H3: a simple
target-state diff is not enough.

**Methodology.** 48-case deterministic endpoint simulator across 12 failure-mode
categories (A–L), three verifier arms scoring the same cases paired, ground truth derived
mechanically from private simulator state and revealed only after predictions were frozen
to disk. Vulnerability presence established through safe state predicates only — no
exploitation. Wilson intervals for proportions, McNemar exact for paired comparisons. Full
detail in `experiments/remediation-verification-v1/methodology.md`.

**Case count.** 48 (8 genuine successes, 40 failures of various kinds). Ground-truth
distribution: 19 `REMEDIATION_FAILED`, 11 `PARTIALLY_REMEDIATED`, 8 `VERIFIED_REMEDIATED`,
4 `REGRESSION_INTRODUCED`, 3 `NEW_SECURITY_RISK`, 3 `INSUFFICIENT_EVIDENCE`.

**Arms.** A `STATUS_ONLY` (execution metadata only) · B `TARGET_STATE` (did the intended
change land) · C `INDEPENDENT_VERIFIER` (vulnerability predicate + persistence projection +
regression smoke tests + duplicate scan + rollout completeness + evidence sufficiency).

**Results.**

| Arm | False-safe | Rate | 95% CI | Accuracy | Macro F1 |
| --- | --- | --- | --- | --- | --- |
| STATUS_ONLY | 38/48 | 79.2% | 65.7–88.3% | 14.6% | 0.044 |
| TARGET_STATE | 34/48 | 70.8% | 56.8–81.8% | 29.2% | 0.222 |
| INDEPENDENT_VERIFIER | 3/48 | 6.2% | 2.1–16.8% | 93.8% | 0.931 |

Paired (false-safe): A→C b=35 c=0, exact p = 5.8e-11, significant. B→C b=31 c=0, exact
p = 9.3e-10, significant. A→B b=6 c=2, exact p = 0.289, **inconclusive**.

**Limitations.** Arm C's decision rule mirrors the ground-truth precedence rule, so its
absolute accuracy is an upper bound and its residual errors reflect collection gaps rather
than reasoning gaps. The corpus is adversarial by construction (40/48 failures), so rates
are corpus-conditional and are not fleet prevalences. Simulator, not real Windows.
Deterministic remediations only; no LLM-generated remediation was scored. Single design
pass by one author.

**Decision.** H1, H2, H3 all supported. Classification: **STRONG SIGNAL**. The
load-bearing finding is not that independent verification beats exit codes — it is that
target-state compliance checking, which device-management platforms already ship, does
*not* significantly reduce false-safe outcomes on this corpus. The sharpened risk is that
all three of Arm C's failures came from silently incomplete collection, which means the
residual risk (and any defensible moat) sits in collection breadth rather than in
verification logic.

**Next experiment.** v2 — make silent collector blindness the primary variable, add a
scope-awareness signal, and have Arm C re-implemented without sight of the ground-truth
derivation to test the shared-design threat.
