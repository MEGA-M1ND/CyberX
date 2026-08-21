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
