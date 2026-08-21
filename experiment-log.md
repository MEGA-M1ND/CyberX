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

---

## 2026-08-21 — EXP-002 — Remediation Verification v2

**Hypothesis.** v1 left one question open: its independent verifier's only remaining failures
were silently incomplete evidence collection. v2 makes collection completeness the independent
variable. H1: false assurance rises monotonically as coverage falls. H2: a scope-aware
fail-closed verifier cuts false assurance by ≥80% versus a scope-unaware one. H3: abstention
rises but verified recall stays operationally acceptable at coverage ≥80%. H4: a bounded
active-evidence verifier recovers verdicts without materially raising false assurance. H5:
adversarial missingness is substantially more dangerous than random missingness.

**Methodology.** Five architectural layers with the leakage boundary enforced by import-graph
tests: latent world → oracle → collector → observation package → verifier. 13 scenario families
× 5 coverage levels × 7 missingness mechanisms × 2 instances = 754 case conditions per
partition, dev and holdout, sharing no seeds. Ground truth is derived by an oracle reading the
latent world; verifiers see only a serialised observation package identified by an opaque
digest. Predictions are frozen to disk before the oracle is imported. Five arms. Full detail in
`experiments/remediation-verification-v2/README.md` and `reports/final-report.md`.

**Case count.** 754 holdout conditions × 5 arms = 3770 verdicts (1508 conditions across both
partitions). Oracle label distribution is 1 remediated family, 7 failed, 3 partial, 1
regression, 1 new-exposure — 58 conditions each.

**Arms.** A `STATUS_ONLY` · B `TARGET_STATE` · C `SCOPE_UNAWARE_INDEPENDENT` (the v1 verifier,
given a flattened evidence view with no collection manifest) · D `SCOPE_AWARE_FAIL_CLOSED`
(same evidence plus the manifest; refuses to verify on missing, stale, disputed or out-of-scope
evidence) · E `ACTIVE_EVIDENCE` (D plus at most three targeted evidence requests).

**Results (holdout).**

| Arm | False assurance (wrong VERIFIED / all VERIFIED) | Unsafe escape (unsafe called VERIFIED / all unsafe) | Abstention | Verified recall | Accuracy |
| --- | --- | --- | --- | --- | --- |
| A | 92.3% (696/754) | 100.0% (638/638) | 0.0% | 100.0% | 7.7% |
| B | 93.4% (354/379) | 48.6% (310/638) | 11.0% | 43.1% | 29.0% |
| C | 81.4% (219/269) | 28.7% (183/638) | 10.6% | 86.2% | 52.1% |
| D | 76.0% (19/25) | 3.0% (19/638) | 69.2% | 10.3% | 27.1% |
| E | 42.2% (19/45) | 3.0% (19/638) | 35.5% | 44.8% | 60.7% |

Under the five mechanisms where the collector describes its own gaps honestly, Arm D's unsafe
escape is 0/440 against Arm C's 132/440 (McNemar b=132, c=0, exact p=3.7e-40). Every remaining
false assurance in Arms D and E — all 19 — comes from `UNDECLARED_GAP`, a sixth mechanism added
by this experiment where the manifest claims coverage the collector did not have. Arm E
recovered 254 of Arm D's 522 abstentions correctly, 0 incorrectly, creating 0 new false
assurances, at 1.09 requests per case against a hard cap of 3.

**Hypothesis verdicts.** H1 **not supported** — Arm C's unsafe escape peaks at 90% coverage
(35.1%) and falls to 22.7% at 40%; nearly-complete evidence is the dangerous region, not sparse
evidence. H2 **supported in counts, not in the rate** — 158 false assurances → 0 under declared
mechanisms, but Arm D's rate is undefined there because it never claims verification, and with
`UNDECLARED_GAP` folded in its rate is nominally worse than Arm C's; the metric chooses the
answer. H3 **not supported** — Arm D's verified recall is 21.4% at 90% coverage and 7.1% at 80%.
H4 **supported**. H5 **supported** — 9.1% (random) vs 30.0% (declared adversarial) vs 48.9%
(undeclared) for Arm C at matched coverage.

**Limitations.** The corpus is adversarial by construction: 12 of 13 families are failures and
5 of 7 mechanisms aim at the decisive field, so Arm D's abstention rate is a property of this
corpus rather than an estimate for a real fleet. The oracle and the verifiers are separate code
with no shared helpers (enforced by test) but not separate minds; absolute accuracy is an upper
bound and `reports/shared-design-threats.md` accounts for the residue. Conditions within a
scenario family are correlated, so cluster-bootstrap intervals over families are reported
alongside Wilson intervals and are much wider. The scope model presumes a collector can
enumerate its own partitions cleanly — exactly what `UNDECLARED_GAP` questions.

**Decision.** **MIXED SIGNAL** (4 of 6 pre-stated STRONG criteria met; harm-detection recall and
verified recall at high coverage both fail). The pre-registered MIXED definition — safety
improves primarily by abstaining on most cases — describes the passive fail-closed arm exactly.
The finding that matters is narrower and more useful than "verification works": *scope awareness
is a complete defence against gaps a collector can describe and no defence at all against gaps
it cannot, and a bounded evidence-request channel is what makes fail-closed verification
operationally survivable.* The startup thesis moves from "verification layer" to "product module
that must own collection", because the value is now clearly located in the collector rather than
in the verifier.

**Next experiment.** v3 — measure the undeclared-gap rate of real endpoint collectors against a
known-state Windows lab image. Falsifier: if undeclared gaps exceed roughly a third of all gaps,
the v2 defence is not worth building. Gated behind `ALLOW_REAL_WINDOWS_LAB=1`, read-only signals
only, disposable VM, no tenant integration.

---

## 2026-08-21 — EXP-003 — Remediation Verification v3 — **BLOCKED_NOT_EXECUTED**

**Hypothesis.** v2 ended with one number deciding the thesis: how often is a real Windows
collector wrong about its own scope, rather than merely narrow? H1: common inventory sources
contain material undeclared gaps for per-user, side-by-side, portable and non-default-path
installations. H2: an independent filesystem/version channel recovers a majority of decisive
package-inventory gaps. H3: a composite active collector reduces decisive undeclared gaps by ≥80%
versus the best single passive collector. H4: cross-collector disagreement is a useful trigger for
abstention or active collection. H5: reliable verification needs targeted collection, not an
exhaustive scan.

**What happened.** The measurement was not taken. This session runs on Linux with no hypervisor,
no PowerShell, and both safety gates unset, so no disposable Windows VM was reachable. Per the
brief's instruction for exactly this case, the harness was built and tested in dry-run mode and
the outcome is recorded as `BLOCKED_NOT_EXECUTED`. **No hypothesis was tested and no result is
claimed.**

**What was built.** Forty deterministic fixtures across the twenty required families, each
declaring its decisive evidence at explicit coordinates (registry view, hive, user scope, package
provider, filesystem root class) plus expected vulnerability, persistence and regression state, a
fixture hash and a cleanup procedure. Six read-only PowerShell collectors with machine-readable
scope contracts, a composite active collector with a bounded widening step, four import-only
vendor-export adapters, a three-gate safety model, a preflight that resolves machine identity and
prints every planned action, a prefix-based cleanup script, and a reproducibility gate.

**Methodology of the fallback.** With no machine to measure, each (fixture, decisive fact,
collector) triple was classified by deduction from the collector's declared scope: a fact outside
reach on a channel that claims completeness for that evidence type is an undeclared gap; outside
reach on a channel that claims nothing is a declared gap. That is a deduction from documented
behaviour, not an observation, and it is labelled `PREDICTED_FROM_CONTRACTS` in every artefact and
at the head of every report.

**Predicted figures (not results).** 480 classifications across 40 fixtures × 10 contracts.
Decisive undeclared-gap rate: uninstall-registry script 50.0% (8/16 of the facts it claims),
`Get-Package` 25.0% (4/16), expanded-registry / file-version / composite 0 silent misses (they
claim completeness for nothing), service/task 0.0% (0/8) with a claim its mechanism supports.
Vendor-export models 12.5%–37.5%. Cross-collector rescue 63.2% (120/190). Active-request success
10/14. Remaining false assurance after composite collection 0/30, with 4 of 48 decisive facts left
unresolved.

**Decision rule.** **WITHHELD.** The rule classifies a measurement. The contract analysis alone
would imply MIXED SIGNAL (4 of 5 criteria), failing on cross-collector rescue at 63.2% against an
80% bar.

**Limitations.** The headline is a deduction from contracts written by the same author as the
collectors that satisfy them, and nothing checks the implementation against a real machine. The
composite's zero silent misses is definitional — a collector claiming completeness for nothing
cannot produce a silent miss — so the denominator-stable companion metric (unresolved decisive
facts, 4/48) is the honest one. Four of ten contracts are unverified models of vendor
documentation. Fixture prevalence is invented: twenty families in equal numbers is not a fleet,
and the frequency of awkward installation patterns, not the gap rate, decides whether any of this
matters. Fixtures use copies of one Microsoft binary with clean version metadata, which is the
friendliest possible case for the file-version channel that the recovery story depends on.

**What the analysis did establish.** Two things that are checkable and did not need a VM. First,
the difference between a collector that produces silent misses and one that does not is about ten
lines of PowerShell — collectors A and B share a mechanism and differ only in reading both
registry views, walking loaded `HKU`, cross-referencing `ProfileList`, and reporting the profiles
they could not read. Second, collector failures are correlated by mechanism: the three
package-inventory channels fail on the same fixtures, so evidence diversity has to be *mechanism*
diversity, and aggregating three registry-derived inventories yields one registry-derived
inventory.

**Startup thesis: unchanged and better specified.** No evidence was added in either direction.
The analysis narrows what a positive result could look like — if the fix for silent misses is a
ten-line patch any management vendor can ship, the defensible position cannot be knowing to read
both registry views. What might survive is the reconciliation layer, the bounded active request,
and the audit artefact; all three are unproven.

**Next experiment.** Run this harness on a disposable Windows VM. The most valuable output is not
the metrics but the prediction-versus-measurement diff, which names every contract that reality
contradicts. After that: measure the prevalence of awkward installation patterns on a real fleet,
test the file-version channel against real vendor binaries rather than one clean Microsoft
executable, and measure the true cost of a widened filesystem scan on a populated machine.
