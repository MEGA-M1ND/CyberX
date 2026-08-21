# Collector gap matrix

> **Measurement status**
> 
> **BLOCKED_NOT_EXECUTED.** No disposable Windows VM was reachable from this session, so no collector was run against a real machine. Reason: this is Linux, not Windows; no disposable Windows lab VM is reachable from this session.
> 
> Every figure below is **PREDICTED FROM COLLECTOR CONTRACTS** - deduced from what each collector's declared scope says it queries, applied to where each fixture's decisive evidence sits. That is a deduction, not a measurement. It says what should happen if the contracts are accurate; the entire point of a lab run is to find out where they are not.
> 
> **Do not cite any number in this experiment as a measured property of real Windows inventory tooling.**

Which channel can settle which fixture family, and what it does when it cannot.

`silent` counts decisive facts a collector misses **while claiming to cover that evidence type completely** - the class v2 showed no verifier can defend against. `declared` counts facts it misses and says so, which a scope-aware verifier can turn into an abstention.

| Collector | Claims complete for | Silent misses | Declared gaps | Decisive facts unresolved | Fixtures fully decided |
| --- | --- | --- | --- | --- | --- |
| A uninstall-registry | PACKAGE_INVENTORY | **8** | 30 | 42/48 | 4/40 |
| B expanded-registry | _nothing_ | **0** | 30 | 34/48 | 12/40 |
| C package-provider | PACKAGE_INVENTORY | **4** | 30 | 38/48 | 8/40 |
| D file-version | _nothing_ | **0** | 32 | 36/48 | 8/40 |
| E service/task | SERVICE_STATE, SCHEDULED_TASK, PERSISTENCE_STATE | **0** | 36 | 40/48 | 5/40 |
| F composite | _nothing_ | **0** | 4 | 4/48 | 36/40 |
| Intune export | PACKAGE_INVENTORY | **2** | 30 | 36/48 | 8/40 |
| Defender export | PACKAGE_INVENTORY | **2** | 20 | 26/48 | 17/40 |
| Tenable export | PACKAGE_INVENTORY | **6** | 18 | 24/48 | 20/40 |
| SCCM export | PACKAGE_INVENTORY | **6** | 20 | 30/48 | 14/40 |

## Decisive undeclared-gap rate

Numerator: decisive facts silently missed. Denominator: decisive facts whose evidence type the collector claims to cover completely. A collector claiming completeness for nothing has no denominator, which is not the same as being safe - see the unresolved column above.

| Collector | Rate | Contract basis |
| --- | --- | --- |
| A uninstall-registry | 50.0% (8/16) | `IMPLEMENTED_IN_THIS_REPOSITORY` |
| B expanded-registry | n/a (0/0) | `IMPLEMENTED_IN_THIS_REPOSITORY` |
| C package-provider | 25.0% (4/16) | `IMPLEMENTED_IN_THIS_REPOSITORY` |
| D file-version | n/a (0/0) | `IMPLEMENTED_IN_THIS_REPOSITORY` |
| E service/task | 0.0% (0/8) | `IMPLEMENTED_IN_THIS_REPOSITORY` |
| F composite | n/a (0/0) | `IMPLEMENTED_IN_THIS_REPOSITORY` |
| Intune export | 12.5% (2/16) | `MODEL_OF_VENDOR_DOCUMENTATION_UNVERIFIED` |
| Defender export | 12.5% (2/16) | `MODEL_OF_VENDOR_DOCUMENTATION_UNVERIFIED` |
| Tenable export | 37.5% (6/16) | `MODEL_OF_VENDOR_DOCUMENTATION_UNVERIFIED` |
| SCCM export | 37.5% (6/16) | `MODEL_OF_VENDOR_DOCUMENTATION_UNVERIFIED` |

## By fixture family

Pooled across the five passive collectors: how many of their decisive-fact readings were silent misses.

| Family | Facts examined | Claimed in scope | Silent misses | Rate |
| --- | --- | --- | --- | --- |
| MACHINE_WIDE_64BIT | 10 | 4 | 0 | 0.0% |
| MACHINE_WIDE_WOW6432 | 10 | 4 | 2 | 50.0% |
| PER_USER_INSTALL | 10 | 4 | 2 | 50.0% |
| SECOND_LOCAL_USER_INSTALL | 10 | 4 | 4 | 100.0% |
| PORTABLE_UNREGISTERED | 10 | 0 | 0 | n/a |
| SIDE_BY_SIDE_SAFE_AND_VULNERABLE | 10 | 0 | 0 | n/a |
| BINARY_VERSION_DIFFERS_FROM_INVENTORY | 10 | 0 | 0 | n/a |
| RENAMED_OR_NONDEFAULT_PATH | 10 | 0 | 0 | n/a |
| RESIDUAL_BINARY_AFTER_UPDATE | 10 | 0 | 0 | n/a |
| DISABLED_SERVICE_WITH_RESTART_MECHANISM | 25 | 4 | 0 | 0.0% |
| SERVICE_STATE_DIFFERS_ACROSS_REBOOT | 10 | 2 | 0 | 0.0% |
| SCHEDULED_TASK_RECREATES_COMPONENT | 10 | 2 | 0 | 0.0% |
| REGISTRY_SPLIT_ACROSS_VIEWS_OR_HIVES | 10 | 0 | 0 | n/a |
| OFFLINE_OR_UNLOADED_USER_HIVE | 10 | 4 | 0 | 0.0% |
| PERMISSION_DENIED_EVIDENCE_PATH | 10 | 0 | 0 | n/a |
| STALE_CACHED_INVENTORY | 10 | 4 | 0 | 0.0% |
| PACKAGE_PRESENT_DECISIVE_FILE_MISSING | 10 | 0 | 0 | n/a |
| PACKAGE_ABSENT_VULNERABLE_BINARY_PRESENT | 10 | 0 | 0 | n/a |
| PARTIAL_DEVICE_OR_APPLICATION_SCOPE | 25 | 4 | 4 | 100.0% |
| CONFLICTING_EVIDENCE_BETWEEN_COLLECTORS | 20 | 4 | 0 | 0.0% |

## By user scope

| Value | Facts | Claimed in scope | Silent misses | Rate |
| --- | --- | --- | --- | --- |
| `current_user` | 15 | 4 | 2 | 50.0% |
| `machine` | 205 | 28 | 6 | 21.4% |
| `other_user_loaded` | 10 | 4 | 4 | 100.0% |
| `other_user_offline` | 10 | 4 | 0 | 0.0% |

## By registry view

| Value | Facts | Claimed in scope | Silent misses | Rate |
| --- | --- | --- | --- | --- |
| `Registry32` | 20 | 4 | 2 | 50.0% |
| `Registry64` | 70 | 28 | 10 | 35.7% |
| `not_registry` | 150 | 8 | 0 | 0.0% |

## By installation type

| Value | Facts | Claimed in scope | Silent misses | Rate |
| --- | --- | --- | --- | --- |
| `appx` | 10 | 4 | 4 | 100.0% |
| `arp_machine` | 30 | 12 | 0 | 0.0% |
| `arp_user` | 30 | 12 | 6 | 50.0% |
| `arp_wow6432` | 10 | 4 | 2 | 50.0% |
| `none_portable` | 30 | 0 | 0 | n/a |
| `not_a_package` | 130 | 8 | 0 | 0.0% |

## By filesystem root

| Value | Facts | Claimed in scope | Silent misses | Rate |
| --- | --- | --- | --- | --- |
| `AppDataLocal` | 10 | 0 | 0 | n/a |
| `NonStandard` | 10 | 0 | 0 | n/a |
| `ProgramData` | 10 | 0 | 0 | n/a |
| `ProgramFiles` | 60 | 0 | 0 | n/a |
| `UserProfile` | 10 | 0 | 0 | n/a |
| `not_a_file` | 140 | 40 | 12 | 30.0% |

## By evidence type

| Value | Facts | Claimed in scope | Silent misses | Rate |
| --- | --- | --- | --- | --- |
| `APPLICATION_HEALTH` | 10 | 0 | 0 | n/a |
| `FILE_PRESENCE` | 10 | 0 | 0 | n/a |
| `FILE_VERSION` | 90 | 0 | 0 | n/a |
| `PACKAGE_INVENTORY` | 80 | 32 | 12 | 37.5% |
| `PERSISTENCE_STATE` | 10 | 2 | 0 | 0.0% |
| `REGISTRY_VALUE` | 10 | 0 | 0 | n/a |
| `SCHEDULED_TASK` | 20 | 4 | 0 | 0.0% |
| `SERVICE_STATE` | 10 | 2 | 0 | 0.0% |

