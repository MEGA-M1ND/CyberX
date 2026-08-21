# Simulation-to-Windows transfer

> **Measurement status**
> 
> **BLOCKED_NOT_EXECUTED.** No disposable Windows VM was reachable from this session, so no collector was run against a real machine. Reason: this is Linux, not Windows; no disposable Windows lab VM is reachable from this session.
> 
> Every figure below is **PREDICTED FROM COLLECTOR CONTRACTS** - deduced from what each collector's declared scope says it queries, applied to where each fixture's decisive evidence sits. That is a deduction, not a measurement. It says what should happen if the contracts are accurate; the entire point of a lab run is to find out where they are not.
> 
> **Do not cite any number in this experiment as a measured property of real Windows inventory tooling.**

v2 measured verification behaviour against a simulated collector whose blindness was manufactured by the experiment. v3 was supposed to replace that simulation with real Windows measurements. It could not, so this file records precisely which v2 assumptions remain untested and what would settle each one.

## v2's model versus the Windows evidence surface

| v2 assumption | Windows analogue | Status after v3 |
| --- | --- | --- |
| Evidence partitions into disjoint scope keys a collector either queries or does not | registry views, hives, per-user profiles, package providers, filesystem roots | **Modelled and encoded, not verified.** The partition structure is real; whether a given collector's boundaries align with it is exactly what a lab run would show. |
| A collector can declare its own scope accurately | `Get-Package` reports a provider; `Get-ChildItem` knows its root list; `Get-Service` is genuinely exhaustive | **Partly demonstrable from the mechanism.** A path-list collector always knows its roots. A registry enumeration knows its views. Whether *shipped* collectors emit that is untested. |
| Some gaps are declared and some are silent, and the split is a property of the collector | the difference between enumerating ProfileList and not | **Reproduced in code.** Collector B differs from collector A by about ten lines and turns every silent miss into a declared one. That is a claim about implementations, and it is checkable. |
| A verifier can request more evidence and sometimes get it | widening a file-version root list, re-running with elevation | **Modelled with a bounded widening step.** Real cost, real failure modes, unmeasured. |
| `UNDECLARED_GAP` is the residual risk | a collector that claims a complete software inventory while reading one hive in one view | **This is the number v3 exists to measure and did not.** |

## What the contract analysis predicts, and what would falsify it

| Prediction | Falsified if a lab run shows |
| --- | --- |
| The ubiquitous uninstall-registry script silently misses 8 of the 48 decisive facts, a 50.0% undeclared-gap rate on what it claims | it reaches per-user or WOW6432Node registrations after all, or reports them as excluded |
| `Get-Package -ProviderName Programs` silently misses 4 | the Programs provider enumerates other users' hives, or declines to claim completeness |
| An expanded registry enumeration that cross-references ProfileList produces zero silent misses | ProfileList enumeration is unavailable or unreliable in practice |
| The filesystem/version channel is the largest independent rescuer | file version metadata is absent or wrong on real vendor binaries often enough to break the channel |
| Unloaded user hives are unreachable read-only | a read-only mechanism exists that this analysis missed |

The fourth is the one most likely to break. Real executables carry inconsistent `FileVersion` and `ProductVersion` metadata, some carry none, and marketing version strings routinely disagree with the version an advisory names. The lab fixtures here use copies of one Microsoft binary with clean metadata, which is the friendliest possible case and is not representative.

## What does not transfer at all

- **Prevalence.** The fixture corpus was constructed to contain every awkward installation pattern in roughly equal numbers. Real fleets are mostly ordinary machine-wide 64-bit installs. Nothing here estimates how often the awkward cases occur, and that frequency decides whether any of this matters.
- **The vendor adapters.** Four of the ten contracts are models of published behaviour with no implementation and no verification. They are the weakest evidence in the experiment and are reported separately for that reason.
- **Cost.** Collection times are contract estimates. A real `Get-ChildItem -Recurse` over a populated `C:\Program Files` is minutes, not the seconds assumed here, and that difference decides whether targeted post-remediation verification is practical.

## The one number that decides the thesis

How often is a real Windows collector wrong about its own scope, rather than merely narrow? v2 showed scope awareness is a complete defence in the first case and no defence in the second. v3's contract analysis predicts the answer depends almost entirely on which collector you use - near-total for the ubiquitous script, zero for one written with ten extra lines. **That prediction is cheap to test and has not been tested.**

