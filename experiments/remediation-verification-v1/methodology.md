# Methodology

## Research question

How often does a remediation system claim that a vulnerability is fixed when the
vulnerable condition actually remains?

## Hypotheses

- **H1** — A baseline that treats `exit_code == 0` (or an equivalent device-management
  success status) as proof of remediation will misclassify unsafe endpoints as remediated.
- **H2** — A verifier using independent security-state checks materially reduces
  `FALSE_SAFE` outcomes.
- **H3** — Verification needs more than a state diff: checking that the intended
  configuration changed still misses duplicate installs, persistence, partial remediation,
  regressions, wrong targets, incomplete rollout, misleading tool success, and
  remediations that create new security issues.

The experiment was designed so that any of these could fail. Category A contains 8 clean
successes so that an arm cannot score well by rejecting everything, and three cases
(`E-04`, `I-03`, `K-03`) are constructed so that the independent verifier is *wrong*.

## Verdict vocabulary

Every arm and the ground truth use exactly one of:

```text
VERIFIED_REMEDIATED  REMEDIATION_FAILED  PARTIALLY_REMEDIATED
REGRESSION_INTRODUCED  NEW_SECURITY_RISK  INSUFFICIENT_EVIDENCE
```

## Endpoint model

An `EndpointState` carries packages (a *list* of versions per package, so side-by-side
installs are representable), registry values, services (`status` + `startup_type`), files
(`exists` + `version`), patches (`installed` + `staged`), a reboot-pending flag, health
checks, and posture flags. It also carries an `available` set naming the evidence classes
the view can speak about at all.

A remediation is a list of ops (`install_package`, `set_registry`, `set_service`,
`delete_file`, `install_patch`, `set_flag`, …) applied by a pure, total function. Same
inputs, byte-identical output state.

### Post-reboot projection

Non-destructive and mechanical: services with `startup_type=automatic` come back running,
`disabled` stay stopped, staged patches become installed, `reboot_pending` clears, and any
case-specific `reboot_effects` are applied last. This is how Category D (safe now, unsafe
after reboot) and Category J (unsafe now, safe after reboot) are told apart — they are
indistinguishable to any point-in-time state check.

## Vulnerability predicates

Declarative JSON with three-valued evaluation. When a predicate needs an evidence class
the state view cannot speak about, the result is `UNKNOWN`, never `False`. This is what
makes fail-closed semantics possible rather than aspirational.

Composite predicates written as `any_of[a, b, c]` have three independently remediable
components, which is what makes `PARTIALLY_REMEDIATED` mechanically decidable.

## Two kinds of blindness

The distinction that drives the most interesting result:

- **Honest blindness** — the collector returns `available = False`. A verifier can and
  should fail closed. (Category L.)
- **Silent blindness** — the collector returns `available = True` with an incomplete
  value: an inventory that omits per-user installs, a registry scope that omits a vendor
  hive, a posture snapshot with no schema for local group membership. Nothing signals the
  gap. (`E-04`, `I-03`, `K-03`.)

## Ground-truth derivation

Computed from the simulator's private post-remediation state, never hand-written.
Precedence, highest first:

1. `INSUFFICIENT_EVIDENCE` — a required evidence class is genuinely uncollectable.
2. Vulnerability state (security dominates functionality):
   still vulnerable now *and* after reboot → `REMEDIATION_FAILED`, or
   `PARTIALLY_REMEDIATED` when a composite predicate is partly fixed or only some fleet
   devices are affected; clean now but vulnerable after reboot → `REMEDIATION_FAILED`
   (not persistent); vulnerable now but clean after reboot → `PARTIALLY_REMEDIATED`
   (staged).
3. `NEW_SECURITY_RISK` — the fix landed but left a new unsafe configuration.
4. `REGRESSION_INTRODUCED` — the fix landed but broke a required application.
5. `PARTIALLY_REMEDIATED` — the rollout did not reach every targeted device.
6. `VERIFIED_REMEDIATED`.

New security risks are evaluated against a **standing library** of risk predicates applied
identically to every case (SMB1 enabled, firewall disabled, real-time protection disabled,
legacy TLS re-enabled, unrestricted script policy, world-writable share, unexpected local
admin, unlimited credential caching). Because the library is the same for all 48 cases,
its presence tells a verifier nothing about which case it is looking at.

## Leakage controls

- Three files, three directories, three loader functions. `load_public_cases()` is the
  only one whose output ever reaches a verifier.
- `VerifierInput` has exactly two fields: `case` and `adapter`.
- Verifier modules may not import from `scorer` or reference ground-truth tokens in
  executable code (asserted by AST + token inspection).
- `run()` writes `results/raw_results.jsonl` before `load_ground_truth` is called; the
  test asserts that ordering in the source text of the function.
- The public case file may not contain the strings `label`, `category`, `outcome`, or any
  verdict name.

## Statistics

- **Wilson score interval** for every proportion — several arms sit near 0 or 1 where the
  Wald interval misbehaves and can leave `[0, 1]`.
- **McNemar's test** for paired comparisons, since all arms score the same 48 cases. The
  **exact binomial** p-value is primary at n = 48; the continuity-corrected chi-square is
  reported alongside.
- Results are labelled `statistically significant` only at p < 0.05 **and** ≥ 6 discordant
  pairs; a small-p / few-pairs result is labelled `directional`; everything else is
  `inconclusive`.

## Reproducibility

Every run records experiment version and revision, UTC timestamp, git commit SHA, Python
version, dependency statement, seed, case-manifest SHA-256 and per-file hashes, verifier
versions, remediation source, and configuration. The corpus is frozen by a manifest hash
covering all three case files.

## Protocol for bugs

If a genuine implementation bug is found: document it, fix it, increment the experiment
revision, and re-run **all** arms over **all** cases. Never selectively re-run failures,
and never re-run because a result is unfavourable. Bugs found during v1 are listed in the
final report.
