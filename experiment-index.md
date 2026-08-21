# Experiment index

Register of experiments in this repository. Newest last. Do not edit historical entries;
append revisions as new rows.

| ID | Slug | Title | Hypothesis (short) | Date | Cases | Arms | Status | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EXP-001 | `remediation-verification-v1` | Endpoint Remediation Verification Benchmark v1 | Execution status is an unsafe proxy for remediation success; independent post-remediation verification reduces false-safe outcomes | 2026-08-21 | 48 | STATUS_ONLY, TARGET_STATE, INDEPENDENT_VERIFIER | Complete (frozen) | STRONG SIGNAL — false-safe 79.2% → 70.8% → 6.2% |
| EXP-002 | `remediation-verification-v2` | Remediation Verification v2 — Evidence Completeness, Adversarial Collector Blindness, and Fail-Closed Verification | Incomplete or misleading evidence drives false assurance; scope-aware fail-closed verification prevents unsafe verified verdicts without becoming useless | 2026-08-21 | 754 holdout (1508 total) | STATUS_ONLY, TARGET_STATE, SCOPE_UNAWARE_INDEPENDENT, SCOPE_AWARE_FAIL_CLOSED, ACTIVE_EVIDENCE | Complete (frozen) | MIXED SIGNAL — unsafe escape 100% / 48.6% / 28.7% / 3.0% / 3.0%, at 69.2% abstention for the passive fail-closed arm |
| EXP-003 | `remediation-verification-v3` | Remediation Verification v3 — Real Windows Collector Blindness and Cross-Collector Evidence Recovery | Real Windows inventory mechanisms silently omit decisive evidence while appearing complete; an independent channel recovers those gaps | 2026-08-21 | 40 fixtures / 20 families / 48 decisive facts | 6 implemented read-only collectors + 4 offline vendor-export models | **BLOCKED_NOT_EXECUTED** — harness complete and tested, no lab VM reachable | Classification WITHHELD. Contract-derived prediction only: undeclared-gap rate 50.0% (uninstall-registry), 25.0% (package provider), 0% (scope-honest channels); cross-collector rescue 63.2% |

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

## EXP-003 — Remediation Verification v3

- **Directory:** `experiments/remediation-verification-v3/`
- **Report:** `experiments/remediation-verification-v3/reports/final-report.md`
- **Status:** `BLOCKED_NOT_EXECUTED`. No disposable Windows VM was reachable (Linux host, no
  hypervisor or PowerShell, both safety gates unset). The harness, fixtures, collectors,
  provisioning plan, preflight and cleanup path are complete and tested; the measurement was not
  taken. Every figure is `PREDICTED_FROM_CONTRACTS` and none is a measured property of real
  Windows tooling.
- **Fixture manifest SHA-256:** `49f5e7ab95f521f58618970cc04423c9e0e2d0316bdaab7d32bfdf10e5578b38`
- **Fixture specifications SHA-256:** `5f9a2142c6849ffddcbac4d97ec6c1b92a69ef17c3bf7147d37505a3c85198f9`
- **Collector contracts SHA-256:** `38e9ba1c10c38c4c53d8204cff9167a8cfa84b199dadd4863293b928a1fb0f4f`
- **Classifications SHA-256:** `b3cb11c6ba9227a3f3761df8b764f1fd36c403580326230ab0449094d717dbd0`
- **Safety:** three independent gates (`ALLOW_REAL_WINDOWS_LAB`, `ALLOW_WINDOWS_FIXTURE_SETUP`,
  `RV3_LAB_CONFIRMATION=<hostname>`); read-only collectors; no `Win32_Product`; import-only vendor
  adapters; nothing vulnerable installed.
- **Supersedes:** nothing. v1 and v2 are preserved unmodified and still reproduce.
- **Next experiment:** run this harness on a disposable Windows VM and publish the
  prediction-versus-measurement diff.
