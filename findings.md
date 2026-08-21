# Findings

Conclusions that survived an experiment, with the evidence and the caveat that qualifies
them. Each entry names the experiment it came from. Entries are not edited when later work
changes our confidence — a follow-up entry supersedes them.

---

## F-001 — Execution status is close to uninformative about remediation outcome
**Source:** EXP-001 · **Confidence:** high within the benchmark, unquantified outside it

A verifier reading only `exit_code`, `execution_status`, and `deployment_status` declared
38 of 48 endpoints remediated when they were not (79.2%, 95% CI 65.7–88.3%). All 38 had
exit code 0 and a tool status of Succeeded or Compliant. The same arm also called a
genuinely fixed endpoint failed because a cleanup step returned 1. Exit codes carry little
information about security state in either direction.

**Caveat:** the corpus is adversarial by construction; 79.2% is not a fleet prevalence.

---

## F-002 — Target-state verification moves errors around rather than removing them
**Source:** EXP-001 · **Confidence:** medium-high

Checking that the remediation's intended configuration change actually landed reduced the
false-safe rate only from 79.2% to 70.8% — not significantly better than the baseline
(McNemar exact p = 0.289 on 8 discordant pairs). It reliably catches "the change did not
land" and reliably misses everything where the change landed without resolving the
vulnerable condition: wrong target, side-by-side install, partial composite remediation,
non-persistence, staged-not-effective, wrong product matched, regression, new risk,
incomplete rollout. It was also *worse* than the status-only baseline on two cases where a
non-zero exit code was a correct warning it discards by design.

**Why it matters:** this is the finding that separates "independent verification" from
"compliance policy", which most device-management platforms already ship.

---

## F-003 — The residual risk of independent verification is collection scope, not logic
**Source:** EXP-001 · **Confidence:** medium (3 cases)

All three of the independent verifier's false-safes came from silent collector blindness:
an inventory that omits per-user installs, a registry scope that omits a vendor hive, a
posture snapshot with no schema for local group membership. Every evidence class reported
`available = True`; every predicate evaluated cleanly. By contrast, *honest* blindness —
a collector that admits it failed — was caught 3/3 by a single fail-closed rule at zero
cost in false failures.

**Implication:** fail-closed semantics are cheap and effective against gaps that announce
themselves, and useless against gaps that do not. Verification is exactly as trustworthy
as the completeness of its collection scope.

---

## F-004 — Verification is a precision problem, not a recall problem
**Source:** EXP-001 · **Confidence:** medium-high

All three arms had 87.5–100% recall on `VERIFIED_REMEDIATED`. The entire spread between
them was precision: 15.6% → 19.0% → 72.7%. Framing this work as "catching more failures"
misstates it. The question a verification layer answers is what a claim of "remediated" is
worth.

---

## F-005 — Nearly-complete evidence is more dangerous than sparse evidence
**Source:** EXP-002 · **Confidence:** medium-high within the benchmark

For a verifier that cannot see its collector's scope, the unsafe-escape rate is 0% at complete
coverage, jumps to 35.1% at 90% coverage, and then *declines* to 22.7% at 40%. The relationship
is a step, not a slope. As coverage keeps falling, whole evidence items disappear rather than
individual fields, and a missing item is visible without a manifest — so the verifier starts
abstaining instead of guessing wrong.

**Implication:** a system reporting "collection coverage 92%" is describing its most dangerous
operating point, not a reassuring one. This was predicted to be monotonic (H1) and is not.

---

## F-006 — Scope awareness is a complete defence against declared gaps and none at all against undeclared ones
**Source:** EXP-002 · **Confidence:** high within the benchmark

Given a collection manifest that honestly describes what was queried, a fail-closed verifier had
0 unsafe escapes in 440 adversarially degraded conditions, against 132/440 for the same verifier
without the manifest (McNemar b=132, c=0, exact p=3.7e-40). When the manifest claimed coverage
the collector did not have, the same verifier escaped 19/88 — statistically indistinguishable
from having no manifest at all.

**Implication:** the defensible asset is a collector that knows and reports its own scope, not
the verification logic sitting on top of it. A verification product built over third-party
telemetry inherits that telemetry's undeclared gaps and has no defence against them. This
sharpens F-003 from v1 into a testable claim: the whole approach hinges on one unmeasured
number, the undeclared-gap rate of real collectors.

---

## F-007 — Fail-closed verification is safe and close to useless until it can ask for more
**Source:** EXP-002 · **Confidence:** medium-high

A passive fail-closed verifier cut unsafe escape from 28.7% to 3.0% — and abstained on 69.2% of
cases, with verified-remediation recall of 7.1% at 80% coverage and overall accuracy (27.1%)
*worse* than the scope-unaware verifier it replaced. Adding a hard cap of three targeted
evidence requests recovered 254 of its 522 abstentions correctly, 0 incorrectly, created 0 new
false assurances, held unsafe escape at 3.0%, and raised accuracy to 60.7% at 1.09 requests per
case.

**Implication:** "fail closed" on its own converts errors into abstentions, which is only a win
if an abstention is cheaper than a wrong answer. The bounded request channel is what turns the
trade from a wash into a gain, and it is a product requirement rather than a nicety.

---

## F-008 — Denominators decide the headline
**Source:** EXP-002 · **Confidence:** high (methodological)

False assurance rate (wrong VERIFIED / all VERIFIED) and unsafe escape rate (unsafe cases called
VERIFIED / all unsafe cases) point in opposite directions for an arm that abstains a lot. The
scope-aware verifier's unsafe escape falls from 28.7% to 3.0% while its false-assurance *rate*
stays at 76% — because the intervention shrinks the very denominator the first metric conditions
on. Under the declared-adversarial mechanisms the rate is undefined entirely, since the arm never
claims verification.

**Implication:** any verification benchmark must state both, plus the abstention rate, or the
choice of metric silently chooses the conclusion. v1's single "false-safe rate" over all cases
would have hidden this.
