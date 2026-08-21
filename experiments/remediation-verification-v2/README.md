# Remediation Verification v2 — Evidence Completeness, Adversarial Collector Blindness, and Fail-Closed Verification

Does incomplete, stale, misleading, or selectively missing endpoint evidence cause a
remediation-verification system to hand out false assurance — and can a verifier that
knows the shape of its own blindness refuse to be fooled without becoming useless?

**Simulation only.** No real endpoints, no network, no exploit code, no registry or
service changes, no subprocess execution of generated content. Vulnerability presence is
established through safe state predicates over package, file, registry, service, patch,
reboot, and posture state.

## Quick start

```bash
python3 run_experiment.py        # dev + holdout, every artefact and report
python3 check_reproducibility.py # manifest hash + two independent prediction passes
pytest -q                        # 100+ tests, no network required
ruff check .                     # lint
```

Python 3.11+. No third-party runtime dependencies.

## Headline result

754 holdout case conditions × 5 arms. Every rate names its denominator.

| Arm | False assurance (wrong VERIFIED / all VERIFIED) | Unsafe escape (unsafe called VERIFIED / all unsafe) | Abstention | Accuracy |
| --- | --- | --- | --- | --- |
| A `STATUS_ONLY` | 92.3% (696/754) | 100.0% (638/638) | 0.0% | 7.7% |
| B `TARGET_STATE` | 93.4% (354/379) | 48.6% (310/638) | 11.0% | 29.0% |
| C `SCOPE_UNAWARE_INDEPENDENT` | 81.4% (219/269) | 28.7% (183/638) | 10.6% | 52.1% |
| D `SCOPE_AWARE_FAIL_CLOSED` | 76.0% (19/25) | **3.0%** (19/638) | **69.2%** | 27.1% |
| E `ACTIVE_EVIDENCE` | 42.2% (19/45) | **3.0%** (19/638) | 35.5% | 60.7% |

Classification: **MIXED SIGNAL** (4 of 6 pre-stated criteria met).

Three things worth knowing before reading further:

- **Every remaining unsafe escape in Arms D and E comes from one condition** —
  `UNDECLARED_GAP`, where the collector's manifest claims coverage it did not have. Under
  the five mechanisms where the collector describes its own gaps honestly, Arm D's unsafe
  escape rate is 0/440.
- **False assurance is not monotonic in coverage.** Arm C's unsafe escape peaks at *90%*
  coverage (35.1%) and falls to 22.7% at 40%. Nearly-complete evidence is the dangerous
  region, because that is where gaps are small enough to be invisible and large enough to
  matter.
- **Passive fail-closed verification buys its safety almost entirely by abstaining.** Arm
  D declines to answer 69% of the time and is *less* accurate overall than the
  scope-unaware arm. Arm E — three evidence requests, capped — recovers 254 of Arm D's 522
  abstentions correctly, with zero new false assurances.

Full analysis: [`reports/final-report.md`](reports/final-report.md).

## Layout

```text
src/rv2/
  vocab.py      closed vocabularies and metric label sets; data only, no decisions
  world/        latent endpoint reality across a timeline; oracle and collector only
  oracle/       ground truth from the latent world (five labels, never abstains)
  collect/      manufactures blindness: coverage level x mechanism x seed
  obs/          the serialised ObservationPackage, CollectionManifest, and the
                observation-side (three-valued) predicate evaluator
  verifiers/    the five arms; import obs/ and vocab/ and nothing else
  bench/        deterministic generation, the freeze-ordered harness, SHA-256 manifests
  metrics/      metrics with explicit denominators, Wilson, cluster bootstrap, McNemar
  analysis/     degradation tables, CSV/SVG output, report generation
cases/          serialised observation packages (gzipped JSONL), per partition
manifests/      per-partition manifests with generation, condition, and observation hashes
artifacts/      results.json, results.csv, confusion-matrices.json, degradation-curves.csv,
                statistical-tests.json, run-metadata.json, frozen predictions
reports/        final-report.md, false-assurance-review.md, collection-degradation.md,
                shared-design-threats.md, degradation-curves.svg
tests/          world, oracle, collection, verifiers, layering, metrics, safety, artefacts
```

## Experiment integrity

Leakage is prevented structurally, not by convention, and each guard has a test:

- Five layers. `tests/test_layering.py` parses the import graph of every verifier module
  and fails if any of them reaches `world`, `oracle`, `collect`, `bench`, or `metrics`, or
  names a ground-truth symbol in executable code.
- Observation packages carry an **opaque digest** as their identifier. The condition id
  spells out the scenario family, coverage level, and mechanism, so it never crosses the
  boundary. A test greps the serialised bytes the arms actually saw for family names,
  truth labels, and mechanism names.
- The oracle and the verifiers share no predicate evaluator and no verdict helper. The
  latent evaluator is two-valued and omniscient; the observation evaluator is three-valued
  and reasons about scope, freshness, and disagreement.
- Predictions are frozen to disk before the oracle is imported. `run_partition` imports
  `derive_truth` *below* the freeze, and a test asserts that ordering in the source text.
- The oracle has no `INSUFFICIENT_EVIDENCE` label: the latent world is always determined.
  Whether the observer had enough evidence is a fact about the collector.
- Dev and holdout partitions share no seeds. The holdout hashes are frozen in
  `FROZEN_MANIFEST` and checked by `check_reproducibility.py`.

Residual coupling — and there is some — is documented in
[`reports/shared-design-threats.md`](reports/shared-design-threats.md).

## Reproducibility

`check_reproducibility.py` is the single command. It verifies the frozen manifest hash,
regenerates the conditions and the generation config, runs two independent prediction
passes, compares them to the frozen predictions on disk, and re-derives the confusion
matrices. Wall-clock latency and the run timestamp are the only excluded fields, and both
are documented as runtime data in `artifacts/run-metadata.json`.

## Safety

- No real-endpoint adapter exists in v2 at all. `ALLOW_REAL_WINDOWS_LAB=1` is retained as
  an explicit future-only gate for the proposed v3 lab work and is not read by any code
  path here.
- `tests/test_safety.py` asserts that no module shells out, opens a socket, calls
  `eval`/`exec`, or imports `urllib`/`winreg`/`ctypes`; and it runs slices of the benchmark
  with `socket` and `subprocess` monkeypatched to raise, proving no network connection or
  process start occurs during a run.
- The single permitted `subprocess` call reads the git SHA for run metadata.
