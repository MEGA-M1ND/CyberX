# Remediation Verification v2 - Evidence Completeness, Adversarial Collector Blindness, and Fail-Closed Verification

- Experiment `remediation-verification-v2` revision `2.0.0`
- Run (UTC) `2026-08-21T13:25:44.159996+00:00` | Python `3.11.15` | git `e963696622d493b9ec8e5792f7cf635488311b71`
- Holdout manifest SHA-256 **`6c7e34998bee81ba21a81b8dc8d9c6cc53f74bca101908501ba9756b1294ab81`**
- Holdout observations SHA-256 `60a3e775adf2eaf8a73cb81902b0a332a82ac83c5dd3d63270a3855eb410a2a4`
- Generation config SHA-256 `8793fd88ee76d1184ed61741ab2689958f78cfa0c47a6d453f3cb0a147bb44b7`
- 754 holdout case conditions x 5 arms = 3770 verdicts. Simulation only; no network, no real endpoint, no exploit code.

**Result classification: MIXED SIGNAL** (4 of 6 pre-stated STRONG-SIGNAL criteria met).

## Executive summary

**1. Does false assurance increase as evidence coverage declines?**  It jumps, then plateaus - it does not climb smoothly. For the scope-unaware independent verifier the unsafe-escape rate goes 0.0% at complete coverage to 35.1% the moment coverage stops being complete, and then *falls* as coverage keeps dropping: 34.4% at 80%, 26.6% at 60%, 22.7% at 40%. The reason is mundane and important: as more evidence disappears, whole evidence items go missing rather than individual fields, and a missing item is visible even without a manifest, so the verifier starts abstaining instead of guessing. **The dangerous region is high coverage, not low coverage.** A 90%-complete collection is more likely to produce a confident wrong answer than a 40%-complete one.

**2. Is adversarial missingness worse than random missingness?**  Substantially, at the same nominal coverage. Arm C's unsafe-escape rate is 9.1% when evidence is dropped without regard to what matters, 30.0% when the loss is aimed at the decisive field, and 48.9% when the collector is also wrong about its own scope. Paired over identical conditions the difference is not marginal: see the statistics section.

**3. Does scope awareness prevent unsafe verified verdicts?**  For gaps the collector knows about, completely. Arm D's unsafe-escape rate over the whole holdout is 3.0% (19/638), against Arm C's 28.7% (183/638). Every one of Arm D's remaining escapes comes from `UNDECLARED_GAP` - the condition where the manifest claims coverage the collector did not have. Under the five declared mechanisms Arm D's unsafe-escape rate is exactly 0.0% (0/440). **Scope awareness is a defence against gaps the collector can describe, and no defence at all against gaps it cannot.**

**4. How much abstention does safety require?**  For passive fail-closed verification, far too much. Arm D abstains on 69.2% of the holdout and on 80.8% of adversarially degraded conditions. Its verified-remediation recall at 90% coverage is 21.4% and at 80% coverage 7.1%. This is the pre-registered definition of a MIXED result: Arm D buys its safety almost entirely by declining to answer.

**5. Does active evidence collection recover useful coverage?**  This is the strongest result in the experiment. With a hard cap of three requests and 1.09 used per case on average, Arm E answered 254 of Arm D's 522 abstentions correctly (48.7%), got **0** of them wrong, and created **0** new false assurances. Its unsafe-escape rate is identical to Arm D's at 3.0% while accuracy rises from 27.1% to 60.7% and abstention falls from 69.2% to 35.5%. Asking for a few specific things is what makes fail-closed verification usable rather than merely safe.

**6. Which evidence types have the highest decision value?**  Ranked by how often a request for them moved the verdict, and by how often their absence alone blocked one - see the evidence-value table below. The short version: **package inventory scope** dominates, because a name-addressed fact can hide in any install scope, so a narrowed inventory poisons every package predicate. Path-addressed evidence (registry keys, file paths) is far cheaper to reason about, because the path pins the partition. Application-health and security-posture evidence is the second-largest blocker, and for a reason worth noticing: they are never needed to prove the vulnerability is gone, only to prove that fixing it cost nothing.

**7. What are the remaining false-assurance cases?**  All 19 of Arm D's and Arm E's are `UNDECLARED_GAP` conditions: the collector returned an incomplete inventory while its manifest declared full coverage. No amount of manifest-reading fixes a manifest that is wrong. `reports/false-assurance-review.md` lists every one.

**8. Standalone company, product module, or feature?**  On this evidence, **a product module, and only if it owns collection.** The verification logic itself is a few hundred lines of deterministic rules with no model in it, and an MDM vendor could implement it in a sprint. What is not cheap is the thing the results say actually matters: a collector that knows and honestly declares its own scope, and an evidence-request path that can widen a query on demand. The full argument, including the case against, is in the startup-thesis section.

**9. What would have to be true in a real Windows environment for this to transfer?**  Four things, none of them established here: that real collectors can report their own scope accurately (the entire result rests on this); that the `UNDECLARED_GAP` rate in practice is low rather than dominant; that a scope-widening request is usually available and usually cheap; and that operators tolerate an abstention rate somewhere between Arm D's and Arm E's rather than switching the whole thing off. See 'Simulation-to-reality gap'.

**10. What is the next falsifiable experiment?**  Measure the undeclared-gap rate of real collectors against a known-state Windows lab image, because that single number decides whether the defence tested here is worth building. Details at the end.

## Hypotheses

| ID | Hypothesis | Verdict |
| --- | --- | --- |
| H1 | False assurance rises monotonically as coverage falls | **Not supported.** Unsafe escape for Arm C peaks at 90% coverage (35.1%) and declines to 22.7% at 40%. The relationship is a step at the first loss of completeness, then a decline as gaps become visible. |
| H2 | Scope-aware fail-closed cuts false assurance by >=80% vs Arm C | **Supported in counts, not in the rate.** Under the five declared mechanisms Arm C makes 158 false assurances and Arm D makes 0. But Arm D's *rate* is undefined there (it never claims verification), and with `UNDECLARED_GAP` included its rate is 86.4% against Arm C's 83.9% - nominally worse. The metric chooses the answer. |
| H3 | Abstention rises but verified recall stays acceptable at coverage >= 80% | **Not supported.** Arm D's verified recall is 21.4% at 90% coverage and 7.1% at 80%. Arm E does far better (71.4% and 57.1%) but still misses the 80% bar. |
| H4 | A bounded active verifier recovers verdicts without materially raising false assurance | **Supported.** 254/522 abstentions recovered correctly, 0 incorrectly, 0 new false assurances, identical unsafe-escape rate. |
| H5 | Adversarial missingness is substantially more dangerous than random | **Supported.** At matched coverage, Arm C's unsafe escape is 9.1% under random loss versus 30.0% under targeted loss and 48.9% under undeclared loss. |

## Experimental design

Five layers, separated so that leakage is a structural impossibility rather than a discipline:

```text
world/    latent endpoint reality across a timeline (baseline -> remediation -> reboot)
oracle/   ground truth, read from the latent world, five labels, never abstains
collect/  manufactures blindness: coverage level x missingness mechanism x seed
obs/      the serialised ObservationPackage and CollectionManifest
verifiers/ import obs/ and vocab/ only - asserted by tests/test_layering.py
```

| Arm | What it receives |
| --- | --- |
| A `STATUS_ONLY` | execution metadata only |
| B `TARGET_STATE` | flat view: merged evidence rows, no manifest; checks the intended change landed |
| C `SCOPE_UNAWARE_INDEPENDENT` | flat view; asks the independent vulnerability question but cannot tell a never-queried field from an absent one |
| D `SCOPE_AWARE_FAIL_CLOSED` | full view: raw per-collector items plus the collection manifest; refuses to verify on missing, stale, disputed, or out-of-scope evidence |
| E `ACTIVE_EVIDENCE` | as D, plus at most three targeted evidence requests |

The flat view is what makes the A/B/C versus D/E boundary structural: it models a verifier reading a normalised inventory table rather than collector transcripts. Timestamps survive into the flat view; the reference points they would have to be compared against - when the remediation finished, when the device rebooted - live only in the manifest. A clock with no zero is not a freshness check.

**Corpus.** 13 scenario families x 5 coverage levels x 7 mechanisms (one at full coverage) x 2 instances = 754 conditions per partition, 1508 in total across dev and holdout. Seeds are SHA-256 of each condition's own identity, so no condition depends on iteration order. Dev and holdout share no seeds. Everything reported here is holdout.

**Mechanisms.** `RANDOM_MISSING` removes cells without regard to importance. `DECISIVE_FIELD_MISSING`, `REGRESSION_EVIDENCE_MISSING`, `STALE_EVIDENCE`, `CONTRADICTORY_EVIDENCE` and `SCOPE_MISMATCH` aim at what matters and declare the loss honestly in the manifest. `UNDECLARED_GAP` is a sixth mechanism added by this experiment: the data is missing and the manifest claims full coverage anyway. It is reported separately throughout, because v1's three residual failures were all of exactly that shape and without it this experiment would only be testing scope awareness against gaps that politely announce themselves.

## Primary results

Every rate below names its denominator. Two of them are easy to confuse and point in opposite directions when an arm abstains a lot.

| Metric | Numerator | Denominator |
| --- | --- | --- |
| `false_assurance_rate` | predictions of VERIFIED_REMEDIATED whose truth is not VERIFIED_REMEDIATED | all predictions of VERIFIED_REMEDIATED |
| `unsafe_escape_rate` | cases whose truth is UNSAFE (REMEDIATION_FAILED, PARTIALLY_REMEDIATED, NEW_SECURITY_RISK) predicted VERIFIED_REMEDIATED | all cases whose truth is UNSAFE |
| `verified_precision` | correct predictions of VERIFIED_REMEDIATED | all predictions of VERIFIED_REMEDIATED |
| `verified_recall` | correct predictions of VERIFIED_REMEDIATED | all cases whose truth is VERIFIED_REMEDIATED |
| `abstention_rate` | predictions of INSUFFICIENT_EVIDENCE | all cases |
| `harm_detection_recall` | cases whose truth is REGRESSION_INTRODUCED or NEW_SECURITY_RISK predicted with that exact label | all cases whose truth is REGRESSION_INTRODUCED or NEW_SECURITY_RISK |
| `harm_not_blessed_rate` | harm cases NOT predicted VERIFIED_REMEDIATED (any other verdict, including INSUFFICIENT_EVIDENCE) | all cases whose truth is REGRESSION_INTRODUCED or NEW_SECURITY_RISK |
| `partial_remediation_recall` | cases whose truth is PARTIALLY_REMEDIATED predicted PARTIALLY_REMEDIATED | all cases whose truth is PARTIALLY_REMEDIATED |

### Whole holdout partition

| Arm | False assurance | Unsafe escape | Abstention | Verified recall | Harm never blessed | Accuracy |
| --- | --- | --- | --- | --- | --- | --- |
| A status | 92.3% (696/754) | 100.0% (638/638) | 0.0% | 100.0% | 0.0% | 7.7% |
| B target | 93.4% (354/379) | 48.6% (310/638) | 11.0% | 43.1% | 26.7% | 29.0% |
| C unaware | 81.4% (219/269) | 28.7% (183/638) | 10.6% | 86.2% | 44.8% | 52.1% |
| D scoped | 76.0% (19/25) | 3.0% (19/638) | 69.2% | 10.3% | 100.0% | 27.1% |
| E active | 42.2% (19/45) | 3.0% (19/638) | 35.5% | 44.8% | 100.0% | 60.7% |

### By missingness mechanism group

**Complete evidence (control)**

| Arm | False assurance | Unsafe escape | Abstention | Verified recall | Harm never blessed |
| --- | --- | --- | --- | --- | --- |
| A status | 92.3% (24/26) | 100.0% (22/22) | 0.0% | 100.0% | 0.0% |
| B target | 90.9% (20/22) | 81.8% (18/22) | 0.0% | 100.0% | 0.0% |
| C unaware | 0.0% (0/2) | 0.0% (0/22) | 0.0% | 100.0% | 100.0% |
| D scoped | 0.0% (0/2) | 0.0% (0/22) | 0.0% | 100.0% | 100.0% |
| E active | 0.0% (0/2) | 0.0% (0/22) | 0.0% | 100.0% | 100.0% |

**Random missingness**

| Arm | False assurance | Unsafe escape | Abstention | Verified recall | Harm never blessed |
| --- | --- | --- | --- | --- | --- |
| A status | 92.3% (96/104) | 100.0% (88/88) | 0.0% | 100.0% | 0.0% |
| B target | 88.9% (56/63) | 55.7% (49/88) | 10.6% | 87.5% | 18.8% |
| C unaware | 55.6% (10/18) | 9.1% (8/88) | 9.6% | 100.0% | 87.5% |
| D scoped | 0.0% (0/1) | 0.0% (0/88) | 49.0% | 12.5% | 100.0% |
| E active | 0.0% (0/2) | 0.0% (0/88) | 37.5% | 25.0% | 100.0% |

**Adversarial, declared in the manifest**

| Arm | False assurance | Unsafe escape | Abstention | Verified recall | Harm never blessed |
| --- | --- | --- | --- | --- | --- |
| A status | 92.3% (480/520) | 100.0% (440/440) | 0.0% | 100.0% | 0.0% |
| B target | 93.8% (240/256) | 48.0% (211/440) | 10.0% | 40.0% | 28.7% |
| C unaware | 82.7% (158/191) | 30.0% (132/440) | 10.0% | 82.5% | 38.8% |
| D scoped | n/a (0/0) | 0.0% (0/440) | 80.8% | 0.0% | 100.0% |
| E active | 0.0% (0/19) | 0.0% (0/440) | 34.2% | 47.5% | 100.0% |

**Adversarial, NOT declared (out-of-brief control)**

| Arm | False assurance | Unsafe escape | Abstention | Verified recall | Harm never blessed |
| --- | --- | --- | --- | --- | --- |
| A status | 92.3% (96/104) | 100.0% (88/88) | 0.0% | 100.0% | 0.0% |
| B target | 100.0% (38/38) | 36.4% (32/88) | 19.2% | 0.0% | 31.2% |
| C unaware | 87.9% (51/58) | 48.9% (43/88) | 17.3% | 87.5% | 18.8% |
| D scoped | 86.4% (19/22) | 21.6% (19/88) | 49.0% | 37.5% | 100.0% |
| E active | 86.4% (19/22) | 21.6% (19/88) | 49.0% | 37.5% | 100.0% |

Read the complete-evidence row first. With nothing hidden, Arms C, D and E are all perfect and indistinguishable. Everything that separates them in this experiment is a property of the evidence, not of the reasoning.

## Confidence intervals

Wilson intervals assume independent observations, and these are not independent: 58 conditions share each scenario family and differ only in how their evidence was damaged. Both are given; the cluster bootstrap - resampling whole families, 2000 draws - is the one to believe, and it is much wider.

| Arm | Unsafe escape | Wilson 95% | Family cluster bootstrap 95% |
| --- | --- | --- | --- |
| A status | 100.0% | 99.4% - 100.0% | 100.0% - 100.0% |
| B target | 48.6% | 44.7% - 52.5% | 31.9% - 63.2% |
| C unaware | 28.7% | 25.3% - 32.3% | 14.9% - 41.4% |
| D scoped | 3.0% | 1.9% - 4.6% | 1.3% - 4.5% |
| E active | 3.0% | 1.9% - 4.6% | 1.3% - 4.5% |

## Statistical comparisons

McNemar over identical conditions, exact binomial p-values, with the discordant odds ratio and risk difference as effect sizes. `b` counts conditions where the first arm errs and the second does not.

| Group | Comparison | Error | b | c | Exact p | Risk diff | Reading |
| --- | --- | --- | --- | --- | --- | --- | --- |
| all conditions | A status -> C unaware | false_assurance | 477 | 0 | 5.13e-144 | +1.000 | statistically significant |
| all conditions | A status -> C unaware | unsafe_escape | 455 | 0 | 2.15e-137 | +1.000 | statistically significant |
| all conditions | A status -> C unaware | wrong_verdict | 343 | 8 | 2.35e-90 | +0.954 | statistically significant |
| all conditions | B target -> C unaware | false_assurance | 232 | 97 | 6.66e-14 | +0.410 | statistically significant |
| all conditions | B target -> C unaware | unsafe_escape | 217 | 90 | 2.95e-13 | +0.414 | statistically significant |
| all conditions | B target -> C unaware | wrong_verdict | 262 | 88 | 3.32e-21 | +0.497 | statistically significant |
| all conditions | C unaware -> D scoped | false_assurance | 200 | 0 | 1.24e-60 | +1.000 | statistically significant |
| all conditions | C unaware -> D scoped | unsafe_escape | 164 | 0 | 8.55e-50 | +1.000 | statistically significant |
| all conditions | C unaware -> D scoped | wrong_verdict | 13 | 202 | 9.44e-45 | -0.879 | statistically significant |
| all conditions | C unaware -> E active | false_assurance | 200 | 0 | 1.24e-60 | +1.000 | statistically significant |
| all conditions | C unaware -> E active | unsafe_escape | 164 | 0 | 8.55e-50 | +1.000 | statistically significant |
| all conditions | C unaware -> E active | wrong_verdict | 173 | 108 | 0.000126 | +0.231 | statistically significant |
| all conditions | D scoped -> E active | false_assurance | 0 | 0 | 1 | +0.000 | inconclusive |
| all conditions | D scoped -> E active | unsafe_escape | 0 | 0 | 1 | +0.000 | inconclusive |
| all conditions | D scoped -> E active | wrong_verdict | 254 | 0 | 6.91e-77 | +1.000 | statistically significant |
| adversarial_declared | A status -> C unaware | unsafe_escape | 308 | 0 | 3.84e-93 | +1.000 | statistically significant |
| adversarial_declared | B target -> C unaware | unsafe_escape | 141 | 62 | 2.97e-08 | +0.389 | statistically significant |
| adversarial_declared | C unaware -> D scoped | unsafe_escape | 132 | 0 | 3.67e-40 | +1.000 | statistically significant |
| adversarial_declared | C unaware -> E active | unsafe_escape | 132 | 0 | 3.67e-40 | +1.000 | statistically significant |
| adversarial_declared | D scoped -> E active | unsafe_escape | 0 | 0 | 1 | +0.000 | inconclusive |
| random_missing | A status -> C unaware | unsafe_escape | 80 | 0 | 1.65e-24 | +1.000 | statistically significant |
| random_missing | B target -> C unaware | unsafe_escape | 45 | 4 | 8.23e-10 | +0.837 | statistically significant |
| random_missing | C unaware -> D scoped | unsafe_escape | 8 | 0 | 0.00781 | +1.000 | directional (few discordant pairs) |
| random_missing | C unaware -> E active | unsafe_escape | 8 | 0 | 0.00781 | +1.000 | directional (few discordant pairs) |
| random_missing | D scoped -> E active | unsafe_escape | 0 | 0 | 1 | +0.000 | inconclusive |
| undeclared_gap | A status -> C unaware | unsafe_escape | 45 | 0 | 5.68e-14 | +1.000 | statistically significant |
| undeclared_gap | B target -> C unaware | unsafe_escape | 13 | 24 | 0.0989 | -0.297 | inconclusive |
| undeclared_gap | C unaware -> D scoped | unsafe_escape | 24 | 0 | 1.19e-07 | +1.000 | statistically significant |
| undeclared_gap | C unaware -> E active | unsafe_escape | 24 | 0 | 1.19e-07 | +1.000 | statistically significant |
| undeclared_gap | D scoped -> E active | unsafe_escape | 0 | 0 | 1 | +0.000 | inconclusive |

**These p-values describe this generated corpus and nothing else.** Conditions within a family are correlated by construction, the family mix is a judgement call rather than a measured fleet distribution, and the corpus is adversarial on purpose. Statistical significance here is evidence that the arms differ on this benchmark, not evidence that they would differ on a real fleet.

## Degradation analysis

![Degradation curves](degradation-curves.svg)

Machine-readable in `artifacts/degradation-curves.csv` (curve data) and `artifacts/results.csv` (per-condition rows). Full tables by coverage, mechanism, family, and request count are in `reports/collection-degradation.md`.

| Coverage | C unsafe escape | D unsafe escape | E unsafe escape | D abstention | E abstention | C verified recall | E verified recall |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 100% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% | 100.0% |
| 90% | 35.1% | 7.1% | 7.1% | 57.7% | 20.9% | 92.9% | 71.4% |
| 80% | 34.4% | 3.9% | 3.9% | 66.5% | 28.0% | 85.7% | 57.1% |
| 60% | 26.6% | 1.3% | 1.3% | 76.9% | 46.2% | 92.9% | 28.6% |
| 40% | 22.7% | 0.0% | 0.0% | 85.7% | 52.2% | 71.4% | 14.3% |

The non-monotonicity in Arm C's curve is the most operationally useful finding here, and it was not predicted. A verification system is at its most dangerous when its evidence is *nearly* complete, because that is where gaps are small enough to be invisible and large enough to matter. Systems that measure their own collection health should treat 'coverage is 92%' as a warning, not a reassurance.

## Evidence value

Which evidence types blocked verdicts, and which requests for them paid off.

| Evidence type requested | Requests | Granted | Moved the decision |
| --- | --- | --- | --- |
| `PACKAGE_INVENTORY` | 235 | 63.0% | 53.6% |
| `SECURITY_POSTURE` | 134 | 54.5% | 54.5% |
| `REBOOT_STATE` | 111 | 55.0% | 55.0% |
| `APPLICATION_HEALTH` | 102 | 48.0% | 48.0% |
| `REGISTRY_STATE` | 81 | 84.0% | 61.7% |
| `FILE_STATE` | 68 | 86.8% | 70.6% |
| `SERVICE_STATE` | 43 | 72.1% | 62.8% |
| `PATCH_STATE` | 38 | 55.3% | 52.6% |
| all types for one device | 12 | 0.0% | 0.0% |

The structural point behind the ranking: a predicate leaf addressed by *name* - a package, a service - could be satisfied in any partition of its evidence type, so a narrowed query makes it unresolvable. A leaf addressed by *path* - a registry key, a file - pins exactly one partition, so a narrowed query only matters if it excluded that path. Package inventory is therefore the most fragile evidence in the system, and the scope of a software-inventory query is the single highest-value thing a collector can report accurately.

## Success criteria

Scored after the results were known, against thresholds fixed in advance. 4 of 6 met.

| Criterion | Met | Detail |
| --- | --- | --- |
| D or E cuts false assurance by >=80% vs C under adversarial missingness | yes | under declared-adversarial missingness Arm C makes 158 false assurances, Arm D 0 and Arm E 0: a 100.0% reduction in count. The rate form of the metric is undefined for Arm D there because it never claims verification at all. |
| Unsafe escape rate at or below 5% | yes | Arm D 3.0%, Arm E 3.0%, against Arm C's 28.7%. |
| Harm-detection recall at or above 90% | **no** | exact-label harm detection is 16.4% for Arm D and 45.7% for Arm E. The weaker property that matters operationally - never calling a harm case remediated - is 100.0% for both, against 44.8% for Arm C. |
| Verified-remediation recall at or above 80% when coverage >= 80% | **no** | at coverage 80% or better the worst verified-recall is 7.1% for Arm D and 57.1% for Arm E. |
| The advantage holds across several scenario families, not one template | yes | 7 of 13 scenario families show a materially lower unsafe-escape rate for Arm D than Arm C: EXIT_ZERO_NO_CHANGE, WRONG_PRODUCT_IDENTITY, SIDE_BY_SIDE_VULNERABLE, SERVICE_RETURNS_AFTER_REBOOT, VULNERABLE_BINARY_ON_DISK, INVENTORY_UPDATED_BINARY_UNCHANGED, NEW_EXPOSURE_INTRODUCED. |
| The active arm's requests are bounded and mostly decision-relevant | yes | 1.09 requests per case against a hard cap of 3; 55.1% of requests measurably shrank the blocking set or settled the verdict. |

**Classification: MIXED SIGNAL.** The pre-registered definition of a MIXED result is that safety improves primarily by abstaining on most cases, and that describes the passive fail-closed arm exactly: Arm D abstains on 69.2% of the holdout. Arm E is the reason this is not a weak result - it holds Arm D's safety while answering about half of what Arm D refuses - but two criteria still fail, and one of them (harm-detection recall) fails badly.

## Counter-evidence

Given equal prominence, because the point of this experiment is to find out whether a thing is worth building, not to conclude that it is.

**1. The defence fails completely against undeclared gaps.** Under `UNDECLARED_GAP`, Arm D's unsafe-escape rate is 21.6% against Arm C's 48.9% - better, but not a defence. Every remaining false assurance in Arms D and E is of this kind. If real collectors are commonly wrong about their own scope rather than merely narrow, the entire result evaporates, and nothing in this experiment establishes which is true.

**2. Passive fail-closed verification is close to operationally useless on its own.** Arm D abstains on 69.2% of conditions and its overall accuracy (27.1%) is *worse* than the scope-unaware arm's (52.1%). A tool that says 'I cannot tell' three times out of four gets switched off, and then the effective false-assurance rate is whatever the thing that replaces it produces.

**3. Exact harm detection collapses under evidence loss for every arm.** Harm-detection recall is 22.4% for Arm C, 16.4% for Arm D and 45.7% for Arm E. Arms D and E never *bless* a harm case, which is the property that matters operationally, but 'I cannot tell whether your fix broke the VPN client' is not the same product as 'your fix broke the VPN client'.

**4. The corpus decides the numbers.** Twelve of thirteen families are failures by construction, and five of the seven degradation mechanisms aim at the decisive field on purpose. Arm D's abstention rate is therefore a property of this corpus, not an estimate of what it would do on a fleet where most remediations work and most evidence gaps are irrelevant. No prevalence claim in this report should be read as a fleet prevalence.

**5. The logic is cheap to copy.** Arm D is roughly 250 lines of rules over a manifest. There is no model, no training data, and no accumulated asset. Any vendor that already owns the collector could implement it, and would do it better, because the hard part is the collector.

**6. Same author, same week, both sides.** The oracle and the verifiers are separate code with no shared helpers, and `tests/test_layering.py` enforces that mechanically. They are not separate *minds*. `reports/shared-design-threats.md` is a full accounting; the short version is that absolute accuracy figures are an upper bound and the C-versus-D comparison is the part that depends least on shared design.

## Threats to validity

**Simulation-to-reality gap.** Post-restart behaviour, staged patches, side-by-side installs and scope partitions are modelled by mechanical rules. Real Windows is messier: servicing-stack ordering, pending file-rename operations, per-user versus machine hive redirection, WMI that returns partial results without saying so. The scope model in `obs/package.py` is the most suspect single assumption: it presumes a collector can enumerate its own partitions cleanly, which is exactly what `UNDECLARED_GAP` exists to question.

**Correlated generated cases.** Every metric is computed over conditions that share scenario families. Cluster-bootstrap intervals are reported for this reason and are much wider than the Wilson intervals; several are undefined because the statistic does not exist on resamples where an arm never claims verification.

**Oracle correctness risk.** The oracle is one function with its own precedence order. `tests/test_oracle.py` checks it against thirteen hand-reasoned family expectations, which confirms it agrees with the author's intent - the one thing that cannot be independently confirmed here. If the oracle's ordering is wrong (for example, if a staged-but-not-rebooted patch should count as remediated rather than partial), every arm is scored against a wrong answer key in the same direction.

**Artificial case prevalence.** See counter-evidence 4.

**Does fail-closed merely convert errors into abstentions?**  For Arm D, largely yes, and the numbers say so plainly: unsafe escape falls from 28.7% to 3.0% while abstention rises from 10.6% to 69.2%. That trade is only worth making if an abstention is cheaper than a wrong 'verified', which depends entirely on what the operator does next. Arm E is the interesting arm precisely because it does not accept that trade: it converts 48.7% of the abstentions back into correct answers at zero measured cost in unsafe escape.

## Safety boundaries

- Simulation only. No registry write, no package install or removal, no service change, no subprocess execution of any generated content, no network call in the benchmark path.
- No exploit code exists in this experiment. Vulnerability presence is established only through safe state predicates over package, file, registry, service, patch, reboot and posture state.
- The real-Windows adapter remains hard-disabled and unimplemented, behind `ALLOW_REAL_WINDOWS_LAB=1`, which is an explicit future-only gate. `tests/test_safety.py` asserts that no real execution path is reachable during a benchmark run, and that no module in `src/rv2` shells out, opens a socket, or calls `eval`/`exec`.
- No third-party runtime dependencies; the test suite needs no network access.

## Startup thesis

v1 ended with the thesis stronger and the risk sharpened: verification beats execution status, but the residual failures were all silently incomplete collection, so the moat - if any - was in collection rather than logic. v2 was built to attack that, and it confirms it in a way that is more useful than encouraging.

**What got stronger.** Scope awareness is a real, complete defence against declared gaps: 0/440 unsafe escapes under the five declared mechanisms, against Arm C's 132/440. And bounded active collection turns a safe-but-useless verifier into a usable one without giving the safety back. That pairing - a manifest that describes its own scope, plus a channel to widen a query - is a coherent product surface, and it is not what MDM compliance policies do today.

**What got weaker.** The value is now clearly located in the *collector*, not the verifier. Arm D is trivially reimplementable; the thing it depends on - an honest scope manifest - is owned by whoever runs the agent. A verification vendor sitting on top of someone else's inventory API inherits that vendor's undeclared gaps and, per these results, has no defence against them at all. The defensible position is therefore either 'we run our own collector' (a much heavier company) or 'we are a module inside the platform that already does' (not a company).

**Net.** The evidence supports a **product module with a collection requirement**, not a standalone verification layer over third-party telemetry. The specific claim that survived contact with data is narrow: *an independent verifier is worth exactly as much as its collector's honesty about scope, and a bounded evidence-request channel is what makes fail-closed verification operationally survivable.* The claim that did not survive is that verification logic on top of existing telemetry is sufficient.

## Next experiment

**v3 - measuring the undeclared-gap rate of real collectors.** One number decides whether any of this matters, and it is not measured here: how often is a real endpoint collector wrong about its own scope, as opposed to merely narrow? Everything in v2 says scope awareness is a complete defence in the first case and no defence in the second.

Falsifiable design, and it does not need a product:

1. Build a Windows lab image with a *known* ground-truth state: a deliberate per-user install, a WOW6432Node key, a second binary outside the default path, a staged servicing -stack update, a disabled-but-auto-start service.
2. Run several read-only collectors over it and capture both what they return and what they claim to have covered.
3. Classify every discrepancy as declared (the collector's own scope report predicts the gap) or undeclared (it does not).
4. **Falsifier:** if undeclared gaps exceed roughly a third of all gaps, the v2 defence is not worth building and the honest conclusion is that endpoint verification cannot be done from telemetry alone.

Gated behind `ALLOW_REAL_WINDOWS_LAB=1`, read-only signals only, a disposable VM with no network path to anything else, and no Intune or tenant integration. Two secondary questions worth folding in: whether an abstention with a named blocker is operationally cheaper than a wrong 'verified' (a human-factors question this benchmark cannot answer), and an independent re-implementation of Arm D against the frozen v2 holdout by someone who has not read `oracle/truth.py`.

---

Holdout manifest SHA-256: `6c7e34998bee81ba21a81b8dc8d9c6cc53f74bca101908501ba9756b1294ab81`
Generation config SHA-256: `8793fd88ee76d1184ed61741ab2689958f78cfa0c47a6d453f3cb0a147bb44b7`
Holdout observations SHA-256 (uncompressed JSONL): `60a3e775adf2eaf8a73cb81902b0a332a82ac83c5dd3d63270a3855eb410a2a4`

