# Shared-design threats

v1's final report named shared design between the oracle and the verifier as its
largest threat to validity: both applied the same precedence rule, so the
verifier's remaining errors could only come from observation gaps.  v2 tried to
reduce that coupling.  This file is an honest account of how far it got.

## What was actually separated

| Coupling in v1 | Status in v2 |
| --- | --- |
| One predicate evaluator shared by oracle and verifier | Two implementations. `world/predicates.py` is two-valued and omniscient; `obs/observed_predicates.py` is three-valued and reasons about scope, freshness, and disagreement. Neither imports the other. |
| One verdict-precedence function | The oracle uses an ordered cascade over the latent world (`oracle/truth.py`). Arm D uses a gate chain: justify-or-refuse first, label second (`verifiers/arm_d_scope_aware.py`). Different shapes, no shared helper. |
| Verifier read adapter state directly | Verifiers receive a serialised `ObservationPackage` and nothing else. Arms A, B and C get a flattened view with no collection manifest at all. |
| Truth label included INSUFFICIENT_EVIDENCE | Removed. The latent world is always determined; whether the observer had enough evidence is a fact about the collector. `TruthLabel` has five members, `Verdict` has six. |
| Cases hand-labelled per scenario | Labels are derived by the oracle from whatever world the generator produced. No condition has an author-chosen answer. |

## What is still coupled

These are real and they are not fixed by the above.

1. **One author designed both sides.** The oracle's notion of "still vulnerable" and the verifiers' notion are different code, but they are the same idea, held by the same person, written in the same week. An independent re-implementation of Arm D against the frozen holdout - without sight of `oracle/truth.py` - is the only real test, and it has not been run.
2. **The vulnerability predicate is given to the verifier.** Every arm receives a correct, machine-checkable definition of the vulnerable condition. Deriving that predicate from an advisory is itself hard and error-prone in production, and errors there would flow straight into every arm.
3. **The scope model is shared vocabulary.** `FULL_SCOPE` in `obs/package.py` defines the partitions, and the collector damages the same partitions the verifier checks. A real collector's blind spots do not come pre-labelled to match a verifier's ontology. `UNDECLARED_GAP` exists precisely to probe what happens when they do not match, and it is the one mechanism where scope awareness buys nothing.
4. **The oracle could be wrong.** It is ~90 lines with its own precedence order. Its outputs are checked against 13 hand-reasoned family expectations in `tests/test_oracle.py`, which is a real but shallow check: it confirms the oracle agrees with the author's intent, which is exactly the thing that cannot be independently confirmed here.
5. **Arms C, D and E share a restart-projection idea.** They implement it separately, but the notion that an automatic service comes back and a staged patch lands is common to all three and to the oracle. If that model of Windows is wrong, every arm is wrong together and the benchmark cannot see it.

## How much of the result this could explain

The comparison that depends least on shared design is **Arm C versus Arm D**, because the two differ in the *information* they receive - one gets a collection manifest, the other does not - rather than in how cleverly they reason. The absolute accuracy figures depend much more on shared design than that comparison does, and should be read as an upper bound in the same way v1's were.

The strongest single piece of evidence that the separation is doing something: under `UNDECLARED_GAP`, where the manifest is wrong rather than merely narrow, Arm D's unsafe escape rate is 21.6% - indistinguishable from Arm C's 48.9%. A verifier that was quietly borrowing the oracle's knowledge would not fail there.

