# Remediation Verification v3 - Real Windows Collector Blindness and Cross-Collector Evidence Recovery

- Experiment `remediation-verification-v3` revision `3.0.0`
- Run (UTC) `2026-08-21T14:39:19.078517+00:00` | Python `3.11.15` | git `9a240f7168f867486a6b8ced11bf0a966481eade`
- Mode **DRY_RUN** | status **BLOCKED_NOT_EXECUTED**
- Fixture manifest SHA-256 **`49f5e7ab95f521f58618970cc04423c9e0e2d0316bdaab7d32bfdf10e5578b38`**
- Full fixture specifications SHA-256 `5f9a2142c6849ffddcbac4d97ec6c1b92a69ef17c3bf7147d37505a3c85198f9`
- Collector contracts SHA-256 `38e9ba1c10c38c4c53d8204cff9167a8cfa84b199dadd4863293b928a1fb0f4f`
- Classifications SHA-256 `b3cb11c6ba9227a3f3761df8b764f1fd36c403580326230ab0449094d717dbd0`
- 40 fixtures across 20 families, 48 decisive facts, 10 collector contracts

> **Measurement status**
> 
> **BLOCKED_NOT_EXECUTED.** No disposable Windows VM was reachable from this session, so no collector was run against a real machine. Reason: this is Linux, not Windows; no disposable Windows lab VM is reachable from this session.
> 
> Every figure below is **PREDICTED FROM COLLECTOR CONTRACTS** - deduced from what each collector's declared scope says it queries, applied to where each fixture's decisive evidence sits. That is a deduction, not a measurement. It says what should happen if the contracts are accurate; the entire point of a lab run is to find out where they are not.
> 
> **Do not cite any number in this experiment as a measured property of real Windows inventory tooling.**

## Executive summary

**The measurement this experiment exists to take was not taken.** No disposable Windows VM was reachable from this session: the host is Linux, no hypervisor or PowerShell is present, and both safety gates are unset. What was built instead is the complete, tested, gated harness - 40 fixtures, six read-only collectors, a provisioning plan, a preflight, and a cleanup path - together with a prediction, derived from each collector's declared scope, of what a lab run would find. The prediction is the hypothesis. It is not the result.

**1. Which real collectors silently missed decisive evidence?**  Predicted, not observed. The ubiquitous uninstall-registry script silently misses 8 decisive facts - 50.0% of the 16 whose evidence type it claims to cover completely - while presenting itself as a complete software inventory. `Get-Package -ProviderName Programs` silently misses 4 of 16 (25.0%). The expanded registry enumeration, the file-version channel and the service/task channel silently miss none - the first two because they decline to claim completeness, the third because its enumeration genuinely is exhaustive.

**2. Which installation patterns caused the most blindness?**  Per-user installations, second-user installations, WOW6432Node registrations, and anything with no package record at all. Every one of them is invisible to a machine-scope 64-bit-view enumeration, and three of the five passive channels are exactly that. The breakdown by user scope in `collector-gap-matrix.md` is the sharpest cut: facts sitting at `current_user` or `other_user_loaded` are where the silent misses concentrate.

**3. How often did collectors incorrectly imply complete coverage?**  Of the 10 contracts modelled, 7 claim completeness for at least one evidence type. Of those, 6 have at least one decisive fact that contradicts the claim. False coverage-claim rates per collector are in the gap matrix; for the ubiquitous script it is 50.0% (8/16).

**4. Which independent channel recovered each gap?**  Cross-collector rescue is 63.2% (120/190). The filesystem/version channel is the single largest rescuer (48 facts), which is the mechanism H2 predicted: inventory answers what is *registered*, a file version answers what is actually *there*, and only the second decides a vulnerability. Full attribution in `cross-collector-recovery.md`.

**5. Were collector failures correlated?**  Strongly, and this is the most useful finding in the analysis. The three package-inventory channels fail on the *same* fixtures, because they share a mechanism - they all read package registrations. Adding a second inventory source buys almost nothing. The only channel that fails independently is the filesystem one, because it queries a different subsystem. **Evidence diversity has to be mechanism diversity; two inventories are one channel.**

**6. Can active collection reduce gaps without exhaustive scanning?**  Predicted yes, with a caveat. A bounded widening - three additional root classes, one request each - satisfies 71.4% (10/14) of the facts the passive union cannot settle. The caveat is that the cost estimate here is a contract number (48s), and a real recursive scan of a populated `C:\Program Files` is minutes, not seconds.

**7. What false-assurance cases remain?**  After composite collection: 0.0% (0/30) of vulnerable fixtures. That number is weaker than it looks. The composite claims completeness for nothing, so it *cannot* produce a silent miss by construction - it converts them into abstentions instead. The honest cost is 4/48 decisive facts left unresolved: two unloaded user hives (unreachable without `reg load`, which is a write) and two application-health facts (no Windows inventory channel models them).

**8. Does the product need its own endpoint agent?**  On this analysis, it needs *a* second mechanism, not necessarily its own agent. Everything that made the difference here - reading both registry views, enumerating ProfileList, checking a file version - is ordinary PowerShell that any management platform can already run. What no existing inventory feed provides is the scope declaration, and that is a property of how the collector reports, not of who owns it.

**9. Can the approach work through Intune / Defender / Tenable exports alone?**  The modelled answer is no, and the models are the weakest evidence here so treat it as a hypothesis. All four vendor exports claim a complete application inventory; all four are predicted to have silent misses (Intune export 2, Defender export 2, Tenable export 6, SCCM export 6). None of them exposes a scope manifest an automated verifier could read, so even where coverage is good the *declaration* v2 showed to be load-bearing is absent.

**10. Does v3 strengthen, narrow or falsify the startup thesis?**  It narrows it, sharply, and it does not confirm anything. See the thesis section.

## Hypotheses

No hypothesis below is supported or refuted, because none was tested against a real machine. Each is recorded with what the contract analysis predicts and what a lab run would have to show to falsify it.

| ID | Hypothesis | Contract prediction | Status |
| --- | --- | --- | --- |
| H1 | Common Windows inventory sources contain material undeclared gaps for per-user, side-by-side, portable and non-default-path installations | 8 and 4 silent misses for the two channels that claim inventory completeness, concentrated in exactly those families | **Untested** |
| H2 | An independent filesystem/version channel recovers a majority of decisive package-inventory gaps | the file channel is the largest single rescuer, but overall rescue is 63.2% - a majority of *all* gaps, not of every kind | **Untested; predicted partially true** |
| H3 | A composite active collector reduces decisive undeclared gaps by >=80% versus the best single passive collector | 100% against the ubiquitous script, undefined against a scope-honest one that already has zero | **Untested; the comparison is ill-posed** |
| H4 | Cross-collector disagreement is a useful trigger for INSUFFICIENT_EVIDENCE or active collection | the conflicting-evidence fixtures are resolvable only by noticing the disagreement; no single channel detects them | **Untested** |
| H5 | Reliable verification requires targeted collection rather than a full-fleet exhaustive scan | the composite settles 36 of 40 fixtures with three bounded widenings rather than a whole-volume scan | **Untested** |

H3 deserves a note beyond its verdict. "The best single passive collector" turns out to be ambiguous in a way that decides the answer: judged by silent misses the best passive collector already scores zero, and judged by fixtures decided it settles 12 of 40. A hypothesis phrased as a percentage reduction cannot survive that ambiguity, and rephrasing it around absolute residual gaps - as the v3 brief itself insists - is the right fix.

## Primary metrics

| Metric | Numerator | Denominator |
| --- | --- | --- |
| `decisive_undeclared_gap_rate` | decisive facts silently missed (UNDECLARED_GAP) by this collector | decisive facts whose evidence type this collector claims to cover completely |
| `fixture_undeclared_gap_rate` | fixtures with at least one decisive undeclared gap | all fixtures |
| `false_coverage_claim_rate` | (fixture, evidence type) completeness claims contradicted by at least one silently missed decisive fact | all (fixture, evidence type) completeness claims this collector makes where a decisive fact of that type exists |
| `verification_feasibility` | fixtures where this collector resolves every decisive fact | all fixtures |
| `cross_collector_rescue_rate` | decisive facts missed by a passive collector that at least one other implemented channel covers | all decisive facts missed by a passive collector |
| `active_request_success_rate` | scope-widening requests the composite collector can satisfy | decisive facts unresolved by the passive union that a widening could reach |
| `remaining_false_assurance_rate` | vulnerable fixtures where the composite collector silently misses a decisive vulnerability fact, so a verifier would bless them | all vulnerable fixtures |
| `harm_fixture_blessed_rate` | regression fixtures whose decisive regression fact is silently missed | all regression fixtures |
| `unresolved_decisive_fact_rate` | decisive facts this collector does not settle, for any reason | all decisive facts across all fixtures |

| Collector | Decisive undeclared-gap rate | Silent misses | False coverage claims | Fixtures decided | Facts unresolved |
| --- | --- | --- | --- | --- | --- |
| A uninstall-registry | 50.0% (8/16) | 8 | 50.0% (8/16) | 4/40 | 42/48 |
| B expanded-registry | n/a (0/0) | 0 | n/a (0/0) | 12/40 | 34/48 |
| C package-provider | 25.0% (4/16) | 4 | 25.0% (4/16) | 8/40 | 38/48 |
| D file-version | n/a (0/0) | 0 | n/a (0/0) | 8/40 | 36/48 |
| E service/task | 0.0% (0/8) | 0 | 0.0% (0/8) | 5/40 | 40/48 |
| F composite | n/a (0/0) | 0 | n/a (0/0) | 36/40 | 4/48 |
| Intune export | 12.5% (2/16) | 2 | 12.5% (2/16) | 8/40 | 36/48 |
| Defender export | 12.5% (2/16) | 2 | 12.5% (2/16) | 17/40 | 26/48 |
| Tenable export | 37.5% (6/16) | 6 | 37.5% (6/16) | 20/40 | 24/48 |
| SCCM export | 37.5% (6/16) | 6 | 37.5% (6/16) | 14/40 | 30/48 |

- **Fixture-level undeclared-gap rate (composite):** 0.0% (0/40)
- **Cross-collector rescue rate:** 63.2% (120/190)
- **Active-request success rate:** 71.4% (10/14)
- **Remaining false-assurance rate after composite collection:** 0.0% (0/30)
- **Regression fixtures incorrectly blessed:** 0.0% (0/2)

Collection cost is a contract estimate in every row and is not a measurement: A uninstall-registry ~1s, B expanded-registry ~4s, C package-provider ~6s, D file-version ~22s, E service/task ~4s, F composite ~48s.

## Decision rule

**WITHHELD.** Withheld. The decision rule classifies a measurement, and no measurement was taken. The predicted classification below is what the contract analysis implies and must not be reported as a result.

Predicted classification if the contract analysis were confirmed: **MIXED SIGNAL** (4 of 5 criteria).

| Criterion | Predicted | Detail |
| --- | --- | --- |
| Composite collection cuts decisive undeclared gaps by >=80% versus the best single passive collector | yes | the comparison is ambiguous and the ambiguity decides the answer. Against the ubiquitous uninstall-registry script the reduction is 100.0% (8 silent misses to 0); against an expanded registry enumeration that declares its exclusions the reduction is undefined, because that collector already has zero silent misses - while deciding only 12 of 40 fixtures against the composite's 36. |
| Fixture-level remaining decisive undeclared gaps at or below 5% | yes | composite fixture-level undeclared-gap rate 0.0% (0/40); residual false assurance on vulnerable fixtures 0.0% (0/30). |
| Cross-collector rescue at or above 80% | **no** | cross-collector rescue 63.2% (120/190), below the 80% bar. The channels that fail together share a mechanism: three of the five are registry enumerations. |
| No regression or new-risk fixture incorrectly blessed | yes | regression fixtures blessed 0.0% (0/2) - but for an unflattering reason: no collector models application health at all, so the fact is a declared gap for every channel and the verifier abstains rather than detects. |
| Collection cost bounded enough for targeted post-remediation use | yes | composite estimated at 48s against 1s for the cheapest passive channel. These are contract estimates, not measurements; a real recursive scan of a populated Program Files is minutes. |

## Counter-evidence

**1. The headline result is a deduction from contracts I wrote.** The collector contracts encode documented Windows behaviour, and the PowerShell in `powershell/` implements them, but nothing here checks that the implementation matches the contract on a real machine. A contract analysis that predicts its own collectors do well is worth very little until it is falsified by a machine.

**2. The composite's perfect silent-miss score is an artefact of a definitional choice.** It claims completeness for nothing, so it cannot produce a silent miss - by construction, not by capability. Any collector can achieve zero silent misses by declining to claim anything. The metric that resists this is unresolved decisive facts, where the composite still leaves 4/48.

**3. Cross-collector rescue came in at 63.2%, well below the 80% the decision rule asks for.** The reason is correlated failure: three of the five passive channels are registry enumerations that fail on the same fixtures. If real channel diversity is this shallow, multi-channel collection helps less than the phrase suggests.

**4. Nothing detects a functional regression.** Two fixtures break a dependent application, and no collector - including the composite - models application health. They are scored as "not blessed" only because everyone abstains. A verification product that cannot tell you whether the fix broke the business is answering half the question.

**5. The vendor adapters are unverified models.** Four of ten contracts describe published behaviour with no implementation behind them. Question 9's answer rests on them and should be treated as a hypothesis, not a finding.

**6. Fixture prevalence is invented.** Twenty families in equal numbers is not a fleet. Real estates are mostly ordinary machine-wide 64-bit installs, which every channel handles. How often the awkward patterns actually occur is unmeasured, and that frequency - not the gap rate - decides whether any of this is worth building.

**7. The friendly-metadata assumption.** Fixtures use copies of one Microsoft binary with clean, consistent version metadata. Real vendor executables carry inconsistent `FileVersion`/`ProductVersion` fields, sometimes none, and marketing versions that disagree with advisory versions. The file-version channel is the linchpin of the recovery story and it is being tested under the friendliest possible conditions.

## Startup thesis

v1: execution status is a poor proxy for remediation success. v2: scope-aware verification defends completely against declared gaps and not at all against undeclared ones, which located the value in the collector rather than the verifier. v3 was meant to measure whether real collectors produce undeclared gaps. It did not, so the thesis has not moved on evidence - but the analysis narrows what a positive result could even look like.

**What narrowed.** If the contract analysis is right, the difference between a collector that produces silent misses and one that does not is about ten lines of PowerShell - enumerate both registry views, walk loaded HKU, cross-reference ProfileList, and report the profiles you could not read. That is not a product. It is a patch to a script, and any management vendor can ship it in a sprint. The defensible position cannot be "we know to read both registry views".

**What might still be defensible.** Three things survive the narrowing, and all three are unproven. First, the *reconciliation* layer: noticing that a package record and a file version disagree, and knowing which one decides. Second, the *bounded active request*: deciding which single additional query is worth its cost, which the v2 result showed is what makes fail-closed verification usable rather than merely safe. Third, the *audit artefact*: a per-fact record of what was checked, what was not, and why - which is a compliance deliverable rather than a technical one.

**What weakened.** The correlated-failure result. If a second evidence channel has to be a genuinely different mechanism to help, then "we aggregate your existing inventory feeds" is not a product either - aggregating three registry-derived inventories yields one registry-derived inventory. The value would have to come from running a filesystem channel, which means either an agent or a management platform willing to run your script. Both are harder businesses than an integration.

**Net: unchanged and better specified.** No evidence was added in either direction. The experiment converted a vague question into a cheap, falsifiable one.

## What a lab run would settle

The harness is complete and gated. On a disposable Windows VM the run is four commands and produces measured versions of every table above, plus a prediction-versus-measurement diff (`prediction_vs_measurement` in `artifacts/results.json`) naming every contract that was wrong. Procedure in `reports/safety-and-lab-procedure.md`.

The single most valuable output would be the diff, not the metrics. The metrics describe a constructed corpus; the diff describes reality disagreeing with documentation, and that is the thing nobody has written down.

Next after that, in order: measure the *prevalence* of awkward installation patterns across a real fleet, because gap rates without prevalence decide nothing; test the file-version channel against real vendor binaries rather than one clean Microsoft executable; and measure the true cost of a widened filesystem scan on a populated machine.

---

Fixture manifest SHA-256: `49f5e7ab95f521f58618970cc04423c9e0e2d0316bdaab7d32bfdf10e5578b38`
Fixture specifications SHA-256: `5f9a2142c6849ffddcbac4d97ec6c1b92a69ef17c3bf7147d37505a3c85198f9`
Collector contracts SHA-256: `38e9ba1c10c38c4c53d8204cff9167a8cfa84b199dadd4863293b928a1fb0f4f`
Provisioning plan SHA-256: `875991010578a5731424dce9a2a500e4b7e796437b0bb13b508be5c0866de4be`
Classifications SHA-256: `b3cb11c6ba9227a3f3761df8b764f1fd36c403580326230ab0449094d717dbd0`

