# Endpoint Remediation Verification Benchmark v1

A reproducible, simulation-only benchmark testing whether an independent verification
layer can reliably determine that an endpoint vulnerability remediation actually
succeeded — or whether treating "the script exited 0" as success creates dangerous
false confidence.

**Everything runs against a deterministic in-memory simulator.** No real endpoints, no
network access, no exploit code, no third-party systems. Vulnerability presence is
established only through safe state predicates (package version, registry value,
service state, file state, patch state, reboot state, posture flags).

## Quick start

```bash
python3 run_experiment.py     # rebuild corpus, run all three arms, score, write the report
pytest -q                     # 86 tests, no network required
```

No third-party runtime dependencies. Python 3.11+.

## What it measures

The primary metric is **false-safe rate**: predicting `VERIFIED_REMEDIATED` when the
ground truth is anything else.

| Arm | What it sees | False-safe rate |
| --- | --- | --- |
| A — `STATUS_ONLY` | execution metadata only | 79.2% |
| B — `TARGET_STATE` | did the intended configuration change land? | 70.8% |
| C — `INDEPENDENT_VERIFIER` | vulnerability predicate, persistence, regression, duplicates, rollout, evidence sufficiency | 6.2% |

Full results, statistics, failure analysis, and the honest case against the thesis are in
[`reports/final-report.md`](reports/final-report.md).

## Layout

```text
cases/
  public/cases.json          verifier-visible case definitions
  simulation/scenarios.json  harness-only: initial state, what the remediation did
  ground_truth/labels.json   scorer-only labels (derived, never hand-written)
  MANIFEST.json              SHA-256 over all three, freezing the corpus
src/rvbench/
  models.py predicates.py cases.py manifest.py runner.py
  simulator/   deterministic endpoint state + remediation-op engine
  adapters/    EndpointAdapter interface, SimulatedEndpointAdapter, WindowsLab stub
  verifiers/   the three arms
  scorer/      ground-truth derivation, metrics, Wilson/McNemar
  remediation/ optional Phase-2 LLM plan generator (off by default)
  analysis/    false-safe review + final report generation
  corpus/      the 48 cases and the emitter
tests/         86 tests
results/       raw_results.jsonl, predictions.csv, metrics.json, ...
reports/       final-report.md, false-safe-review.md
```

## Experiment integrity

- The three case files live in separate directories and are loaded by separate functions.
  A verifier arm receives only a `PublicCase` and an `EndpointAdapter`.
- Predictions are written to `results/raw_results.jsonl` **before** the ground-truth file
  is opened; `tests/test_leakage.py` asserts that ordering in the source of `run()`.
- Ground-truth labels are computed from the simulator's private state by
  `scorer/ground_truth.derive()`, and a test asserts the stored file matches a fresh
  derivation for every case.
- The corpus is frozen by a SHA-256 manifest covering all three case files, so any edit
  — including to a label — invalidates a previously reported result.

## Safety

- `WindowsLabAdapter` raises unless `ALLOW_REAL_WINDOWS_LAB=1`, and raises
  `NotImplementedError` even then. Not used by v1.
- The optional LLM remediation generator is off unless `RVBENCH_LLM_ENABLED=1` and an API
  key are set. It emits a JSON plan in the simulator's op schema, which is
  schema-validated and executed only by the simulator — never by a shell.
- `tests/test_safety_and_llm.py` asserts no module shells out, opens sockets, or calls
  `eval`/`exec`.
