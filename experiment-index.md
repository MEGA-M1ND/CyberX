# Experiment index

Register of experiments in this repository. Newest last. Do not edit historical entries;
append revisions as new rows.

| ID | Slug | Title | Hypothesis (short) | Date | Cases | Arms | Status | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EXP-001 | `remediation-verification-v1` | Endpoint Remediation Verification Benchmark v1 | Execution status is an unsafe proxy for remediation success; independent post-remediation verification reduces false-safe outcomes | 2026-08-21 | 48 | STATUS_ONLY, TARGET_STATE, INDEPENDENT_VERIFIER | Complete (frozen) | STRONG SIGNAL — false-safe 79.2% → 70.8% → 6.2% |
| EXP-002 | `remediation-verification-v2` | Remediation Verification v2 — Evidence Completeness, Adversarial Collector Blindness, and Fail-Closed Verification | Incomplete or misleading evidence drives false assurance; scope-aware fail-closed verification prevents unsafe verified verdicts without becoming useless | 2026-08-21 | 754 holdout (1508 total) | STATUS_ONLY, TARGET_STATE, SCOPE_UNAWARE_INDEPENDENT, SCOPE_AWARE_FAIL_CLOSED, ACTIVE_EVIDENCE | Complete | MIXED SIGNAL — unsafe escape 100% / 48.6% / 28.7% / 3.0% / 3.0%, at 69.2% abstention for the passive fail-closed arm |

## EXP-001 — Endpoint Remediation Verification Benchmark v1

- **Directory:** `experiments/remediation-verification-v1/`
- **Report:** `experiments/remediation-verification-v1/reports/final-report.md`
- **Case-manifest SHA-256:** `a9878fb4a3e202f47f3ccca027621e5d34358276c49da18fe454e7875db0de79`
- **Environment:** deterministic simulator only; no network, no real endpoints, no exploit code.
- **Next experiment:** v2 — collection completeness under adversarial blindness.

## EXP-002 — Remediation Verification v2

- **Directory:** `experiments/remediation-verification-v2/`
- **Report:** `experiments/remediation-verification-v2/reports/final-report.md`
- **Holdout manifest SHA-256:** `6c7e34998bee81ba21a81b8dc8d9c6cc53f74bca101908501ba9756b1294ab81`
- **Generation config SHA-256:** `8793fd88ee76d1184ed61741ab2689958f78cfa0c47a6d453f3cb0a147bb44b7`
- **Environment:** deterministic simulator only; no network, no real endpoints, no exploit code.
- **Supersedes:** nothing. v1 is preserved unmodified as a frozen artifact and still reproduces.
- **Next experiment:** v3 — measure the undeclared-gap rate of real endpoint collectors against a
  known-state Windows lab image, gated behind `ALLOW_REAL_WINDOWS_LAB=1`.
