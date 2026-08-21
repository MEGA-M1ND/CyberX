# Cross-collector recovery

> **Measurement status**
> 
> **BLOCKED_NOT_EXECUTED.** No disposable Windows VM was reachable from this session, so no collector was run against a real machine. Reason: this is Linux, not Windows; no disposable Windows lab VM is reachable from this session.
> 
> Every figure below is **PREDICTED FROM COLLECTOR CONTRACTS** - deduced from what each collector's declared scope says it queries, applied to where each fixture's decisive evidence sits. That is a deduction, not a measurement. It says what should happen if the contracts are accurate; the entire point of a lab run is to find out where they are not.
> 
> **Do not cite any number in this experiment as a measured property of real Windows inventory tooling.**

When one channel misses a decisive fact, does another channel have it?

**Cross-collector rescue rate: 63.2% (120/190).**

Numerator: decisive facts missed by a passive collector that at least one other implemented channel covers. Denominator: all decisive facts missed by a passive collector. The composite collector is excluded from the rescuer set - it is built from these channels, so counting it as an independent rescuer would make the metric circular.

## Which channel does the rescuing

| Rescuing channel | Facts it covers that another passive channel missed |
| --- | --- |
| D file-version | 48 |
| B expanded-registry | 40 |
| E service/task | 32 |
| C package-provider | 24 |
| A uninstall-registry | 12 |

The filesystem/version channel is the largest single rescuer, which is the mechanism H2 predicted: package inventory answers *what is registered*, and a file version answers *what is actually there*. Those are different questions and only the second one decides a vulnerability.

## What nothing rescues

Decisive facts no passive channel covers:

- **DISABLED_SERVICE_WITH_RESTART_MECHANISM** / `dependent_app_health`
- **OFFLINE_OR_UNLOADED_USER_HIVE** / `offline_hive_entry`
- **PACKAGE_ABSENT_VULNERABLE_BINARY_PRESENT** / `orphan_binary_version`
- **PARTIAL_DEVICE_OR_APPLICATION_SCOPE** / `scoped_app_health`
- **PARTIAL_DEVICE_OR_APPLICATION_SCOPE** / `scoped_arp_entry`
- **PERMISSION_DENIED_EVIDENCE_PATH** / `restricted_binary_version`
- **PORTABLE_UNREGISTERED** / `portable_binary_version`
- **RENAMED_OR_NONDEFAULT_PATH** / `renamed_binary_version`

These fall into three groups, and the grouping is the useful part:

1. **Outside every default path list** - portable executables, renamed binaries, orphaned installs under a user profile. Recoverable, but only by widening the search, which is what the composite's active step does.
2. **Behind an access boundary** - a directory the collector cannot read, an unloaded user hive. The first is recoverable with elevation; the second is not recoverable at all without a write.
3. **Not modelled by any Windows inventory channel** - application health. No amount of cross-collection helps, because no collector asks the question.

## Bounded active collection

**Active-request success rate: 71.4% (10/14).**

Numerator: scope-widening requests the composite collector can satisfy. Denominator: decisive facts unresolved by the passive union that a widening could reach.

The composite collector widens the file-version search one root class at a time, up to a cap of three widenings. What it cannot satisfy is exactly group 2 and group 3 above.

Requests that no widening can satisfy:

- `fx-39a5010b9588ad25` / `dependent_app_health`
- `fx-6b982ad56d8ea88a` / `offline_hive_entry`
- `fx-deb17a35d5976d29` / `scoped_app_health`
- `fx-e6a1b4cd0faf1471` / `offline_hive_entry`

## Are the failures correlated?

Yes, and in a way that matters. The registry channels (A, B, C) fail *together* on per-user, second-user, and non-ARP installs, because they share a mechanism: they all read package registrations. Adding a second registry-based channel buys almost nothing. The only channel that fails independently is the filesystem one, because it asks a different question of a different subsystem.

This is the practical form of the finding: **evidence-channel diversity has to be mechanism diversity.** Two inventories are one channel.

