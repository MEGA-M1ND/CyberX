# Experiment index

Register of experiments in this repository. Newest last. Do not edit historical entries;
append revisions as new rows.

| ID | Slug | Title | Hypothesis (short) | Date | Cases | Arms | Status | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EXP-001 | `remediation-verification-v1` | Endpoint Remediation Verification Benchmark v1 | Execution status is an unsafe proxy for remediation success; independent post-remediation verification reduces false-safe outcomes | 2026-08-21 | 48 | STATUS_ONLY, TARGET_STATE, INDEPENDENT_VERIFIER | Complete | STRONG SIGNAL — false-safe 79.2% → 70.8% → 6.2% |

## EXP-001 — Endpoint Remediation Verification Benchmark v1

- **Directory:** `experiments/remediation-verification-v1/`
- **Report:** `experiments/remediation-verification-v1/reports/final-report.md`
- **Case-manifest SHA-256:** `a9878fb4a3e202f47f3ccca027621e5d34358276c49da18fe454e7875db0de79`
- **Environment:** deterministic simulator only; no network, no real endpoints, no exploit code.
- **Next experiment:** v2 — collection completeness under adversarial blindness.
