# Remediation Verification v3 — Real Windows Collector Blindness and Cross-Collector Evidence Recovery

> ## BLOCKED_NOT_EXECUTED
>
> **No real Windows collection was performed.** This session runs on Linux with no
> hypervisor, no PowerShell, and both safety gates unset, so no disposable Windows VM was
> reachable. What exists here is the complete, tested, gated harness plus a prediction —
> derived from each collector's declared scope contract — of what a lab run would find.
>
> **Every number in this experiment is `PREDICTED_FROM_CONTRACTS`. None of it is a measured
> property of real Windows inventory tooling.** The prediction is the hypothesis a lab run
> would test, not its result.

v2 established that scope-aware verification is a complete defence against collection gaps a
collector *declares*, and no defence at all against gaps it does not. All 19 of v2's residual
unsafe escapes were the second kind. v3 asks whether real Windows inventory mechanisms produce
that second kind of gap, how often, and whether a second collection channel recovers it.

## Quick start

```bash
python3 run_experiment.py --preflight-only   # what would run, against which machine
python3 run_experiment.py                    # run or block, then write artefacts and reports
python3 check_reproducibility.py             # manifest hash + two classification passes
pytest -q                                    # 112 tests, no network, no Windows required
ruff check .
```

Python 3.11+. No third-party runtime dependencies.

## Predicted result

40 fixtures across 20 families, 48 decisive facts, 10 collector contracts.

| Collector | Claims complete for | Decisive undeclared-gap rate | Silent misses | Fixtures decided |
| --- | --- | --- | --- | --- |
| A uninstall-registry | `PACKAGE_INVENTORY` | **50.0%** (8/16) | 8 | 4/40 |
| B expanded-registry | _nothing_ | n/a (0/0) | 0 | 12/40 |
| C package-provider | `PACKAGE_INVENTORY` | **25.0%** (4/16) | 4 | 8/40 |
| D file-version | _nothing_ | n/a (0/0) | 0 | 8/40 |
| E service/task | service, task, persistence | 0.0% (0/8) | 0 | 5/40 |
| F composite | _nothing_ | n/a (0/0) | 0 | **36/40** |
| Intune / Defender / SCCM / Tenable exports | `PACKAGE_INVENTORY` | 12.5% – 37.5% | 2–6 | 8–20/40 |

Cross-collector rescue **63.2%** (120/190) · active-request success **10/14** · remaining false
assurance after composite collection **0/30**.

Three things worth knowing:

- **The difference between a collector that silently misses evidence and one that does not is
  about ten lines of PowerShell.** Collectors A and B use the same family of mechanism. B reads
  both registry views, walks loaded `HKU`, cross-references `ProfileList`, and reports the
  profiles it could not read — and drops from 8 predicted silent misses to 0.
- **Collector failures are correlated.** The three package-inventory channels fail on the same
  fixtures because they share a mechanism. Adding a second inventory source buys almost nothing;
  the only independent rescuer is the filesystem channel. Evidence diversity has to be
  *mechanism* diversity.
- **The composite's zero silent misses is a definitional artefact, not a capability.** It claims
  completeness for nothing, so it cannot produce a silent miss by construction — it converts them
  into abstentions. Its honest cost is 4 of 48 decisive facts left unresolved: two unloaded user
  hives (unreachable read-only, since `reg load` is a write) and two application-health facts (no
  Windows inventory channel models them).

The decision-rule classification is **WITHHELD**. The rule classifies a measurement, and no
measurement was taken.

Full analysis: [`reports/final-report.md`](reports/final-report.md).

## Layout

```text
src/rv3/
  vocab.py        closed vocabularies: gap classes, evidence types, scope dimensions, gates
  fixtures/       fixture specification, the 40-fixture catalog, hashing and the provisioning plan
  contracts/      the collector scope contract and the ten contracts
  collectors/     the gated real-collection path and offline vendor-export importers
  lab/            safety gates and the preflight
  analysis/       gap classification, metrics, artefacts, report generation
  runner.py       preflight -> run or block -> classify -> score
powershell/       six read-only collectors, the fixture provisioner, the cleanup script
fixtures/         (populated on a lab run)
manifests/        fixture manifest and provisioning plan, both hashed
artifacts/        results.json, results.csv, gap-classifications.csv, collector-contracts.json,
                  raw-observations.json, fixture-manifest.json, run-metadata.json, preflight.txt
reports/          the six required reports
tests/            gates, PowerShell read-only audit, fixtures, isolation, analysis, artefacts
```

## Safety

This experiment may run against exactly one kind of machine: a disposable Windows VM you are
prepared to destroy. Three independent conditions must all hold:

| Gate | Purpose |
| --- | --- |
| `ALLOW_REAL_WINDOWS_LAB=1` | permits running read-only collectors on a real machine |
| `ALLOW_WINDOWS_FIXTURE_SETUP=1` | permits creating or removing fixtures — the only writing path |
| `RV3_LAB_CONFIRMATION=<hostname>` | the operator naming the target, checked against the live hostname |

The third gate is deliberately not a boolean: a flag can be set by a stray environment file;
typing the name of the machine you are about to modify cannot be done by accident. Both the
Python harness and the PowerShell scripts check all three independently. A non-Windows host is
refused before the gates are even considered.

- **Never** against the host machine, a corporate endpoint, a production tenant, a live
  Intune/Configuration Manager/Defender environment, or any machine not designated as the lab.
- **Nothing vulnerable is installed and no exploit is reproduced.** A "vulnerable" fixture is a
  version string below a threshold sitting at a particular coordinate — built from copies of
  `notepad.exe`, synthetic ARP entries, lab-namespace registry values, and disposable services,
  tasks and local accounts, all under `RV3Lab_` / `rv3lab_` prefixes.
- **`Win32_Product` is never used.** Enumerating it triggers an MSI consistency check against
  every registered product, which can reconfigure software as a side effect of a supposedly
  read-only query. Excluded by name in the contracts, the PowerShell, and the tests.
- Vendor adapters are **import-only**: they read a file exported by hand and have no live-tenant
  code path.
- `tests/test_powershell_readonly.py` audits every collector script for mutating cmdlets,
  `Win32_Product`, `reg load`, and network cmdlets. `tests/test_safety_gates.py` proves real
  collection is unreachable without all three gates and asserts the gate check precedes any
  `subprocess` reference in every writing entry point.

Procedure, requirements, and the exact commands for a real run:
[`reports/safety-and-lab-procedure.md`](reports/safety-and-lab-procedure.md).

## Ground-truth independence

- Fixture ids are opaque digests. The family name, every expectation, and the decisive
  coordinates are ground truth and never reach a collector.
- A collector receives only `collector_view()`: the fixture id and the lab roots to look under.
  Targets are the union of plausible locations, not the decisive coordinates, so pointing a
  collector at a fixture does not hand it the answer.
- `tests/test_isolation.py` asserts no collector module imports the fixture catalog, no
  collector-side code names an expectation, and no PowerShell script hard-codes a decisive
  locator or a fixture id.
- On a real run the provisioner returns what the machine actually reported after each fixture was
  created, and that observation is hashed into the manifest — so ground truth rests on the
  specification *and* a direct observation.

## What a lab run would add

The most valuable output is not the metrics — it is the prediction-versus-measurement diff
(`prediction_vs_measurement` in `artifacts/results.json`), which names every contract that turned
out to be wrong. The metrics describe a constructed corpus; the diff describes reality
disagreeing with documentation.
