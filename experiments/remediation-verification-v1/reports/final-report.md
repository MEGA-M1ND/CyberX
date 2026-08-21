# Endpoint Remediation Verification Benchmark v1 - final report

- Experiment: `remediation-verification-v1` revision `1.0.0`
- Run (UTC): `2026-08-21T11:35:35.238063+00:00`
- Case-manifest SHA-256: **`a9878fb4a3e202f47f3ccca027621e5d34358276c49da18fe454e7875db0de79`**
- Git commit: `unavailable`  |  Python `3.11.15`  |  seed `20260821`
- Adapter: `SimulatedEndpointAdapter` (simulation only; real-endpoint adapters disabled)

## Executive summary

**Does treating successful script execution as proof of remediation create dangerous false confidence?** On this benchmark, yes, and by a wide margin. A verifier that reads only execution metadata declared 38 of 48 endpoints remediated when they were not - a false-safe rate of 79.2% (95% Wilson CI 65.7%-88.3%). Every one of those cases had exit code 0 and a management-tool status of Succeeded or Compliant.

**Did independent post-remediation verification materially reduce that risk?** Yes. The independent verifier's false-safe rate was 6.2% (3/48; CI 2.1%-16.8%), an absolute reduction of 72.9 percentage points against the status-only baseline, with 35 cases fixed and 0 newly broken (McNemar exact p = 5.82e-11, statistically significant).

**The result that matters most for product strategy is the third comparison.** Simple target-state verification - the "did my configuration change land?" check that most device-management platforms already ship - reduced the false-safe rate only to 70.8%. Against the status-only baseline that difference is **inconclusive** (b = 6, c = 2, exact p = 0.289): checking that the intended change landed is not, on this corpus, a meaningful defence against false confidence. The independent verifier beat target-state verification by 64.6 percentage points (exact p = 9.31e-10, statistically significant).

Classification against the pre-registered thresholds: **STRONG SIGNAL**. The independent verifier removed the large majority of false-safe outcomes, and - critically - the value did *not* collapse into what a straightforward target-state check already provides.

Two caveats belong in the summary rather than buried in the limitations. First, these rates are properties of a deliberately adversarial 48-case corpus, not estimates of how often real fleets fail; 40 of 48 cases were constructed to fail in some way. Second, the independent verifier's decision rule and the ground-truth derivation share the same precedence logic, so Arm C's residual errors come only from observation gaps, not from reasoning gaps. That is the single largest threat to validity in this experiment and is discussed in full below.

## Research question

How often does a remediation system claim that a vulnerability is fixed when the vulnerable condition actually remains?

## Hypotheses

| ID | Hypothesis | Outcome |
| --- | --- | --- |
| H1 | Execution status is insufficient: an `exit_code == 0` baseline misclassifies unsafe endpoints as remediated | **Supported** - 79.2% false-safe rate |
| H2 | Independent verification materially reduces false-safe outcomes | **Supported** - 6.2% vs 79.2%, exact p = 5.82e-11 |
| H3 | Verification needs more than a state diff | **Supported** - target-state verification left 70.8% false-safe (not significantly better than the baseline: inconclusive, exact p = 0.289); the independent verifier beat it on 31 cases and lost on 0, exact p = 9.31e-10 |

## Experimental design

Three verifier arms score the same 48 cases, paired. All three receive exactly two inputs: the public case definition and an `EndpointAdapter`. None can reach the scenario file, the ground-truth labels, or the scorer - enforced by module structure and asserted by `tests/test_leakage.py`.

| Arm | Information set |
| --- | --- |
| A - STATUS_ONLY | execution metadata only (`exit_code`, `execution_status`, `deployment_status`) |
| B - TARGET_STATE | the remediation's declared target-state assertions, evaluated on every enumerable device; fails closed on missing evidence; deliberately ignores exit codes so a noisy-but-effective script does not fool it |
| C - INDEPENDENT_VERIFIER | execution metadata + target state + independent vulnerability predicate + post-reboot persistence projection + regression smoke tests + duplicate-install scan + rollout completeness + evidence sufficiency |

Execution order is the experimental control and is asserted in code: load public cases -> load scenarios -> apply remediation -> run A, B, C -> **freeze predictions to `results/raw_results.jsonl`** -> only then load ground truth -> score.

Ground truth is not hand-written. It is derived mechanically from the simulator's private post-remediation state by `scorer/ground_truth.derive()`, and a test asserts the stored label file matches a fresh derivation for all 48 cases. Precedence: insufficient evidence > vulnerability state > new security risk > functional regression > rollout completeness > verified.

Vulnerability presence is established only through safe state predicates - package version, registry value, service state, file presence/version, patch state, reboot state, posture flags. No exploitation, no network activity, no third-party systems.

## Benchmark corpus

48 cases across 12 categories, 8 of them genuine successes so that an arm cannot score well by rejecting everything.

| Category | Cases | Arm A false-safes | Arm B false-safes | Arm C false-safes |
| --- | --- | --- | --- | --- |
| A - genuine successful remediation | 8 | 0 | 0 | 0 |
| B - exit 0 but nothing changed | 4 | 4 | 0 | 0 |
| C - wrong target changed | 4 | 4 | 4 | 0 |
| D - temporary remediation | 4 | 4 | 4 | 0 |
| E - side-by-side vulnerable version remains | 4 | 4 | 4 | 1 |
| F - partial remediation | 4 | 2 | 4 | 0 |
| G - partial fleet rollout | 4 | 4 | 3 | 0 |
| H - functional regression | 4 | 4 | 4 | 0 |
| I - new security risk introduced | 3 | 3 | 3 | 1 |
| J - reboot required | 3 | 3 | 3 | 0 |
| K - incorrect vulnerability match | 3 | 3 | 3 | 1 |
| L - evidence missing | 3 | 3 | 2 | 0 |

Ground-truth label distribution: `INSUFFICIENT_EVIDENCE` 3, `NEW_SECURITY_RISK` 3, `PARTIALLY_REMEDIATED` 11, `REGRESSION_INTRODUCED` 4, `REMEDIATION_FAILED` 19, `VERIFIED_REMEDIATED` 8.

Three cases (`E-04`, `I-03`, `K-03`) model **silent collector blindness**: the evidence collector reports a complete inventory that is not complete. They exist so that Arm C has a genuine, non-zero failure mode rather than an artificially perfect score.

## Primary results - false-safe rate

A false-safe is a prediction of `VERIFIED_REMEDIATED` against any ground-truth label other than `VERIFIED_REMEDIATED`.

| Arm | False-safes | Rate | 95% Wilson CI |
| --- | --- | --- | --- |
| Arm A - STATUS_ONLY | 38 / 48 | **79.2%** | 65.7% - 88.3% |
| Arm B - TARGET_STATE | 34 / 48 | **70.8%** | 56.8% - 81.8% |
| Arm C - INDEPENDENT_VERIFIER | 3 / 48 | **6.2%** | 2.1% - 16.8% |

Absolute differences:

| Comparison | Δ false-safe rate | Δ accuracy | Δ VERIFIED_REMEDIATED precision |
| --- | --- | --- | --- |
| STATUS_ONLY -> TARGET_STATE | -8.3 pp | +14.6 pp | +3.5 pp |
| STATUS_ONLY -> INDEPENDENT_VERIFIER | -72.9 pp | +79.2 pp | +57.2 pp |
| TARGET_STATE -> INDEPENDENT_VERIFIER | -64.6 pp | +64.6 pp | +53.7 pp |

## False-safe analysis

Every one of the 75 false-safe predictions across all arms is enumerated in `reports/false-safe-review.md`, with the initial vulnerable state, the remediation action, the reported execution status, the post-remediation state, the post-reboot projection, the reason codes the arm emitted, the true vulnerability predicate, and the missing signal. `results/false_safe_review.json` holds the machine-readable form.

The distinct mechanisms behind them:

**Arm A - one mechanism, repeated.** All 38 failures share a single cause: the arm reads no post-remediation security state at all. It is fooled identically by a no-op installer that returns 0, by a script that hardens the wrong registry hive, by a service stop that does not survive reboot, by a staged patch, by a broken line-of-business app, and by a rollout that reached 7 of 10 devices. It is also fooled in the opposite direction: `A-08` genuinely fixed the endpoint while a cleanup step returned exit 1, and Arm A called it a failure. Exit codes carry almost no information about security state in either direction.

**Arm B - one mechanism, more interesting.** Arm B catches exactly the class of failure where the intended change did not land (Category B, all 4 caught) and correctly declines when its own evidence is missing (`L-01`). It is defeated everywhere the change *did* land but did not resolve the vulnerable condition: the wrong target was changed (C), the old build stayed side-by-side (E), only one component of a composite vulnerability was addressed (F), the change does not survive reboot (D), the change is staged and not yet effective (J), the remediation targeted the wrong product (K), the fix broke something (H), the fix created a new exposure (I), or the rollout never reached part of the fleet (G-01, G-02, G-04). Arm B is also *worse* than Arm A on two cases (`F-03`, `F-04`), where a non-zero exit code happened to be a correct warning that Arm B discards by design. This is why the A-to-B comparison is inconclusive: target-state verification changes *which* cases you get wrong more than *how many*.

**Arm C - three failures, all the same mechanism.** `E-04` (a side-by-side vulnerable build the inventory does not enumerate), `I-03` (a local-admin change outside the posture snapshot's schema), and `K-03` (a vulnerable registry key outside the configured collection scope). In all three, every evidence class reported `available = True` and every predicate evaluated cleanly - the collector did not know it was blind, so the verifier had no signal to fail closed on. **This is the residual risk of the entire approach**: an independent verifier is exactly as trustworthy as the completeness of its collection scope, and incompleteness that announces itself (Category L, all 3 caught) is a fundamentally easier problem than incompleteness that does not.

## Secondary results

| Metric | Arm A | Arm B | Arm C |
| --- | --- | --- | --- |
| Overall accuracy | 14.6% | 29.2% | 93.8% |
| Macro F1 | 0.044 | 0.222 | 0.931 |
| VERIFIED_REMEDIATED precision | 15.6% | 19.0% | 72.7% |
| VERIFIED_REMEDIATED recall | 87.5% | 100.0% | 100.0% |
| False-failure rate | 2.1% | 0.0% | 0.0% |
| Insufficient-evidence rate (emitted) | 0.0% | 2.1% | 6.2% |
| Regression detection | 0.0% | 0.0% | 100.0% |
| Partial-remediation detection | 0.0% | 9.1% | 100.0% |
| New-security-risk detection | 0.0% | 0.0% | 66.7% |
| Insufficient-evidence detection | 0.0% | 33.3% | 100.0% |
| Fleet-partial-rollout flagged | 0.0% | 25.0% | 100.0% |
| Mean verifier latency (ms) | 0.005 | 0.090 | 2.082 |

Note the recall column: all three arms have high or perfect recall on `VERIFIED_REMEDIATED`. The arms differ almost entirely in **precision** - how much a claim of 'remediated' is worth. Arm A's precision is 15.6%; Arm C's is 72.7%. Arm C also never produced a false failure, which matters operationally: a verifier that cries wolf gets switched off.

No LLM verifier was used; v1 is deterministic, so token counts and cost are not applicable. Latencies are in-process simulation timings and are not meaningful as real-world estimates.

## Statistical analysis

All arms scored the same 48 cases, so comparisons are paired and use McNemar's test. The exact binomial p-value is primary (n = 48 is small); the continuity-corrected chi-square is reported for reference. `b` counts cases where the first arm errs and the second does not.

| Comparison | Metric | b | c | Discordant | Exact p | χ² (cc) | Interpretation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| STATUS_ONLY vs TARGET_STATE | false_safe | 6 | 2 | 8 | 0.289 | 1.12 | inconclusive |
| STATUS_ONLY vs TARGET_STATE | accuracy | 7 | 0 | 7 | 0.0156 | 5.14 | statistically significant |
| STATUS_ONLY vs INDEPENDENT_VERIFIER | false_safe | 35 | 0 | 35 | 5.82e-11 | 33.03 | statistically significant |
| STATUS_ONLY vs INDEPENDENT_VERIFIER | accuracy | 38 | 0 | 38 | 7.28e-12 | 36.03 | statistically significant |
| TARGET_STATE vs INDEPENDENT_VERIFIER | false_safe | 31 | 0 | 31 | 9.31e-10 | 29.03 | statistically significant |
| TARGET_STATE vs INDEPENDENT_VERIFIER | accuracy | 31 | 0 | 31 | 9.31e-10 | 29.03 | statistically significant |

Read carefully, this table says three things. (1) Independent verification beats both other arms on false-safes with no case made worse in either comparison (`c = 0` both times) and p-values far below any reasonable threshold. (2) Target-state verification is significantly better than status-only on *overall accuracy* but **not** on the primary metric, false-safe rate - it moves errors around rather than removing them. (3) With 48 cases we can support directional claims comfortably where discordance is large (31-38 pairs) and should not read anything into the 8-pair A-versus-B false-safe comparison.

## Failure modes

Ranked by how much they distinguish the arms:

1. **Misleading tool success (B, C, K).** The single largest source of Arm A error and the easiest to argue about in the abstract - until you notice Arm B still fails all of C and K, because the script really did change something, just not the thing that mattered.
2. **Persistence (D) and staging (J).** Both look identical to a point-in-time state check and are opposite in meaning: D is safe now and unsafe later; J is unsafe now and safe later. Only an arm that projects the post-reboot state separates them. Arm B calls both remediated.
3. **Side-by-side installs (E).** The most under-appreciated: the fixed version is genuinely present, so every positive assertion passes. Detecting it requires asking whether *any* installed version is still vulnerable, not whether the fixed one exists.
4. **Composite / partial remediation (F).** Verifiers that check the remediation's own declared targets are structurally incapable of catching this, because the script's declared target is only what it tried to do.
5. **Rollout completeness (G).** Requires comparing devices *confirmed* against devices *targeted*. Devices that never checked in are invisible to per-device checks - which is exactly how they escape.
6. **Collateral damage (H, I).** A fix that breaks a required application or opens a new exposure is not a successful remediation. Neither is visible to any check that only looks at the vulnerability being fixed.
7. **Evidence gaps (L) and silent blindness (E-04, I-03, K-03).** The distinction between these two is the most important engineering lesson in the experiment: fail-closed handles the first perfectly and the second not at all.

## Unexpected findings

1. **Target-state verification is not a meaningful defence against false confidence.** Going in, the plausible outcome was that Arm B would capture most of Arm C's value and leave a thin margin. It did not: 70.8% versus 79.2%, inconclusive. The verification value lives almost entirely in asking the independent question, not in checking the change.
2. **Arm B is worse than Arm A on two cases.** `F-03` and `F-04` returned non-zero exit codes that were genuinely informative; Arm B discards exit codes by design and calls both remediated. A more sophisticated verifier is not automatically a superset of a cruder one.
3. **Recall was never the problem.** Every arm has 87.5-100% recall on `VERIFIED_REMEDIATED`. The entire spread is in precision. Framing verification as 'catching more failures' understates it; the product question is what a 'remediated' claim is worth.
4. **Fail-closed is cheap and effective where blindness is honest.** Arm C caught 3/3 Category L cases with a single rule, at zero cost in false failures.

## Implementation bugs found

1. **Wilson interval floating-point dust.** `wilson_interval(0, n)` returned a lower bound of `6.9e-18` instead of exactly 0, so the interval did not bracket the point estimate. Found by `test_wilson_interval_brackets_the_point_estimate`. Fixed by clamping the bounds to the point estimate (the Wilson interval brackets it analytically, so this only removes FP error). All three arms were re-run from scratch afterwards, per protocol - no case was selectively re-run.
2. **Leakage-guard false positives.** The first version of the leakage test matched the token `scorer` inside a module docstring, and the safety test matched `exec(` inside the helper named `_exec(`. Both were test bugs rather than product bugs; the checks now strip docstrings/comments and use word-boundary matching. Worth recording because a leakage guard that cries wolf is a leakage guard that gets deleted.

No bug was found that changed any verdict, and no result in this report was produced by a selective re-run.

## Threats to validity

**1. Arm C's decision rule mirrors the ground-truth derivation rule.** This is the dominant threat. `verifiers/independent.py` and `scorer/ground_truth.py` apply the same precedence ordering; they differ only in that the verifier reads the *observable* state and the scorer reads the *true* state. The two modules are independent code with no shared imports (asserted by test), but they are not independent *designs*. Consequently Arm C's 93.8% accuracy measures the completeness of its collection scope, not the difficulty of the reasoning. A real verifier faces a harder problem: it does not know the ground-truth precedence rule, and real vulnerability predicates are not handed to it in machine-checkable form. **Arm C's absolute numbers should be read as an upper bound.** The comparative result - that target-state checking does not capture this value - is more robust, because it depends on which signals each arm consumes rather than on how well Arm C reasons.

**2. Corpus construction determines the rates.** 40 of 48 cases are failures, and the category mix is a judgement call, not a measured fleet distribution. The false-safe rates are corpus-conditional and must not be quoted as real-world prevalences. What generalises is the *ordering* of the arms and the *mechanisms* behind each failure, not the percentages.

**3. The simulator is a model, not an endpoint.** Post-reboot behaviour, staged patches, and side-by-side installs are modelled by mechanical rules. Real Windows behaviour is messier (servicing stack ordering, pending-rename operations, per-user vs machine scope, WMI unreliability). The simulator is deliberately generous to the verifier on these points.

**4. Vulnerability predicates are given.** Every case hands all arms a correct, machine-checkable definition of 'vulnerable'. In production, deriving that predicate from an advisory or a scanner finding is itself a hard, error-prone problem, and errors there would flow straight into Arm C.

**5. Deterministic remediations only (Phase 1).** No LLM-generated remediation was scored, so this experiment says nothing about verification under generation noise.

**6. Single author, single design pass.** The corpus, the verifier, and the ground-truth rule were designed together. Independent re-implementation of Arm C against a frozen corpus would be a far stronger test.

## Limitations

- n = 48; adequate for the large effects observed, not for fine-grained comparisons (the A-vs-B false-safe comparison rests on 8 discordant pairs and is reported as inconclusive).
- Windows-shaped scenarios only; no macOS, Linux, or mobile posture modelling.
- No adversarial endpoint: nothing in the simulation actively hides from the collector beyond the three configured blind spots.
- No cost model: real verification means real collection, and collection has agent, bandwidth, and latency costs this experiment does not measure.
- Confidence scores are hand-assigned constants per decision path and are not calibrated.

## Security and safety boundaries

- Everything ran in-process against `SimulatedEndpointAdapter`. No external IP was contacted, no third-party system touched, no tenant modified.
- No exploit code exists anywhere in this experiment. Vulnerability presence is established exclusively through safe state predicates (package version, registry value, service state, file state, patch state, reboot state, posture flags).
- `WindowsLabAdapter` is a documented placeholder that raises unless `ALLOW_REAL_WINDOWS_LAB=1` and raises `NotImplementedError` even then, so it cannot silently become a live path.
- The optional LLM generator is off unless `RVBENCH_LLM_ENABLED=1` and an API key are set. Model output is parsed as a JSON plan in the simulator's own op schema, schema-validated, and executed only by the simulator. No generated text reaches a shell or a real endpoint.
- `tests/test_safety_and_llm.py` asserts that no module shells out, opens sockets, or calls `eval`/`exec`, and that `urllib` appears only in the opt-in generator.
- No third-party runtime dependencies; the test suite requires no network access.

## Startup / product implications

The proposed position in the stack:

```text
Tenable / Defender / Qualys / Rapid7   (finding)
            v
AI remediation                          (action)
            v
Intune / SCCM / Jamf / Workspace ONE    (delivery)
            v
Independent verification                <- the layer under test
            v
audit evidence
```

**Evidence for the thesis.**

- The delivery layer's own success signal is close to uninformative about security outcome on this corpus (79.2% false-safe). If autonomous remediation is going to close findings without a human reading each one, something has to independently establish that the finding is actually closed.
- The value is not already provided by configuration-baseline checking. That is the load-bearing result: Arm B reached only 70.8%, inconclusive against the baseline. A buyer who says "my MDM already does compliance policies" is, on this evidence, describing Arm B.
- The signals that did the work - persistence projection, duplicate-install scanning, rollout completeness, regression smoke tests, standing risk predicates, fail-closed evidence handling - are cross-vendor and adapter-shaped. None require privileged access beyond read-only inventory that management platforms already collect. That is a favourable integration story.
- The output is naturally an audit artefact: verdict, confidence, reason codes, and observed evidence. Compliance evidence is a real budget line in a way that "better verification" is not.

**Evidence against the thesis.** This deserves equal weight.

- **Arm C is a few hundred lines of deterministic code with no model in it.** Everything it does is rules over collected state. That is an argument for this being a *feature* of an existing platform rather than a company - and the platforms already have the collection layer, which is the expensive part.
- **The residual failure mode is collection scope, not verification logic.** All three of Arm C's false-safes came from a collector that was silently incomplete. A verification vendor sitting on top of someone else's inventory inherits exactly that blindness and cannot engineer around it. The defensible moat, if there is one, is in collection breadth and in knowing where collectors lie - which is a harder and less glamorous business than verification logic.
- **The corpus is adversarial by construction.** If real fleets fail in these ways 5% of the time rather than 83% of the time, the pain may not clear the bar for a new procurement.
- **Arm C's accuracy is an upper bound** for the reasons in Threats to Validity. Some of its apparent superiority is a designed-in information advantage.

**Net assessment: the thesis is stronger than before this experiment, with a sharpened risk.** The specific claim that survived contact with data is narrow and useful: *execution status and target-state compliance are both inadequate proxies for remediation success, and they are inadequate in different ways.* The claim that did **not** get support - and was not tested - is that the verification logic itself is defensible IP. The next experiment should attack collection completeness, because that is where both the residual risk and the plausible moat now appear to be.

## Next experiment

**Endpoint Remediation Verification Benchmark v2 - collection completeness under adversarial blindness.** Concretely:

1. **Invert the corpus emphasis.** Make silent collector blindness the primary variable rather than a 3-case residual: vary collection scope systematically (machine vs per-user scope, 32/64-bit hive coverage, MSI vs AppX vs portable installs, stale inventory age) and measure how the false-safe rate degrades with scope. The interesting output is a curve, not a point.
2. **Add a scope-awareness signal.** Test whether a verifier that models what its collector *cannot* see - and downgrades to `INSUFFICIENT_EVIDENCE` accordingly - recovers the three cases Arm C missed, and at what cost in false failures. That trade-off is the real product question.
3. **Break the shared-design threat.** Have Arm C re-implemented against the frozen v1 corpus without sight of `scorer/ground_truth.py`, and re-measure. If accuracy drops sharply, v1's absolute numbers were mostly information advantage.
4. **Phase 2 remediation generation.** Score LLM-generated remediation plans through the same arms to see whether generation noise changes the verification picture, reported separately so it cannot contaminate the verification benchmark.
5. **Isolated Windows lab adapter** (`WindowsLabAdapter`), gated behind `ALLOW_REAL_WINDOWS_LAB=1`, read-only signals only - installed software inventory, registry state, services, file versions, KB/patch state, reboot state, event logs, benign application smoke tests - against a disposable VM or Windows Sandbox with no network path to anything else. Purpose: measure how far the simulator's mechanical reboot/staging rules diverge from real behaviour. Still no Intune tenant integration.

---

Artifacts: `results/raw_results.jsonl` (frozen predictions), `results/predictions.csv`, `results/metrics.json`, `results/confusion_matrices.json`, `results/case_failures.csv`, `results/false_safe_review.json`, `results/run_metadata.json`, `reports/false-safe-review.md`.

Case-manifest SHA-256: `a9878fb4a3e202f47f3ccca027621e5d34358276c49da18fe454e7875db0de79`
