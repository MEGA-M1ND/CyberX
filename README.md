# CyberX

Defensive security research. Each experiment is a self-contained, reproducible study with
a stated hypothesis, a frozen benchmark corpus, machine-readable results, and an honest
write-up — including results that argue against the thesis being tested.

**Safety boundary for the whole repository:** everything runs against simulators, unit
tests, or explicitly isolated local fixtures. No scanning of third-party systems, no
exploit code, no production or tenant changes. Any future adapter that touches a real
machine must be gated behind an explicit opt-in environment flag and default to disabled.

## Experiments

See [`experiment-index.md`](experiment-index.md) for the register, [`experiment-log.md`](experiment-log.md)
for the running log, and [`findings.md`](findings.md) for accumulated conclusions.

| ID | Experiment | Status | Report |
| --- | --- | --- | --- |
| EXP-001 | [Endpoint Remediation Verification Benchmark v1](experiments/remediation-verification-v1/) | Complete (frozen) | [final-report.md](experiments/remediation-verification-v1/reports/final-report.md) |
| EXP-002 | [Remediation Verification v2 — Evidence Completeness and Fail-Closed Verification](experiments/remediation-verification-v2/) | Complete | [final-report.md](experiments/remediation-verification-v2/reports/final-report.md) |

## Running an experiment

```bash
cd experiments/remediation-verification-v2   # or -v1
python3 run_experiment.py
python3 check_reproducibility.py
pytest -q
```

Earlier experiments stay runnable and reproducible. v1 still reproduces its published manifest
hash unchanged after v2 was added.

Python 3.11+. No third-party runtime dependencies; tests require no network access.

## Conventions

- One directory per experiment under `experiments/<slug>/`, versioned in the slug.
- `README.md` + `methodology.md` at the experiment root; `cases/`, `src/`, `tests/`,
  `results/`, `reports/` beneath it.
- Ground truth is stored separately from anything a system under test can read, and is
  derived mechanically rather than hand-labelled wherever possible.
- Every corpus is frozen by a SHA-256 manifest before the final run. The hash is quoted in
  the report; changing any case invalidates the result.
- Results artifacts are committed. Re-running must reproduce them.
