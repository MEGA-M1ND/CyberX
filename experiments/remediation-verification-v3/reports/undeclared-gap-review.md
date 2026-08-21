# Undeclared-gap review

> **Measurement status**
> 
> **BLOCKED_NOT_EXECUTED.** No disposable Windows VM was reachable from this session, so no collector was run against a real machine. Reason: this is Linux, not Windows; no disposable Windows lab VM is reachable from this session.
> 
> Every figure below is **PREDICTED FROM COLLECTOR CONTRACTS** - deduced from what each collector's declared scope says it queries, applied to where each fixture's decisive evidence sits. That is a deduction, not a measurement. It says what should happen if the contracts are accurate; the entire point of a lab run is to find out where they are not.
> 
> **Do not cite any number in this experiment as a measured property of real Windows inventory tooling.**

Every decisive fact a collector would silently miss: **28** across all collectors and all 40 fixtures.

A silent miss is a fact the collector does not reach *and does not report as missing*, on an evidence type it presents as complete. It is the only gap class that survives a scope-aware verifier, which is why it is the whole subject of this experiment.

| Fixture | Family | Fact | Evidence type | Collector | Why it is invisible |
| --- | --- | --- | --- | --- | --- |
| `fx-01812717b5791792` | MACHINE_WIDE_WOW6432 | `arp_version_wow` | PACKAGE_INVENTORY | A uninstall-registry | Registry32 view not queried; provider `arp_wow6432` not enumerated |
| `fx-aab83b7701794b16` | MACHINE_WIDE_WOW6432 | `arp_version_wow` | PACKAGE_INVENTORY | A uninstall-registry | Registry32 view not queried; provider `arp_wow6432` not enumerated |
| `fx-8e578b8bb474c4d0` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | A uninstall-registry | provider `appx` not enumerated |
| `fx-deb17a35d5976d29` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | A uninstall-registry | provider `appx` not enumerated |
| `fx-514d93ae61272984` | PER_USER_INSTALL | `arp_version_hkcu` | PACKAGE_INVENTORY | A uninstall-registry | HKCU hive not queried; user scope `current_user` not enumerated; provider `arp_user` not enumerated |
| `fx-82c8f58d82cf730c` | PER_USER_INSTALL | `arp_version_hkcu` | PACKAGE_INVENTORY | A uninstall-registry | HKCU hive not queried; user scope `current_user` not enumerated; provider `arp_user` not enumerated |
| `fx-da63098dbc5ef8b4` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | A uninstall-registry | HKU hive not queried; user scope `other_user_loaded` not enumerated; provider `arp_user` not enumerated |
| `fx-832cb05b91aec9ad` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | A uninstall-registry | HKU hive not queried; user scope `other_user_loaded` not enumerated; provider `arp_user` not enumerated |
| `fx-8e578b8bb474c4d0` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | C package-provider | provider `appx` not enumerated |
| `fx-deb17a35d5976d29` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | C package-provider | provider `appx` not enumerated |
| `fx-da63098dbc5ef8b4` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | C package-provider | HKU hive not queried; user scope `other_user_loaded` not enumerated |
| `fx-832cb05b91aec9ad` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | C package-provider | HKU hive not queried; user scope `other_user_loaded` not enumerated |
| `fx-da63098dbc5ef8b4` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | Defender export | HKU hive not queried; user scope `other_user_loaded` not enumerated |
| `fx-832cb05b91aec9ad` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | Defender export | HKU hive not queried; user scope `other_user_loaded` not enumerated |
| `fx-da63098dbc5ef8b4` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | Intune export | HKU hive not queried; user scope `other_user_loaded` not enumerated |
| `fx-832cb05b91aec9ad` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | Intune export | HKU hive not queried; user scope `other_user_loaded` not enumerated |
| `fx-8e578b8bb474c4d0` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | SCCM export | provider `appx` not enumerated |
| `fx-deb17a35d5976d29` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | SCCM export | provider `appx` not enumerated |
| `fx-514d93ae61272984` | PER_USER_INSTALL | `arp_version_hkcu` | PACKAGE_INVENTORY | SCCM export | HKCU hive not queried; user scope `current_user` not enumerated; provider `arp_user` not enumerated |
| `fx-82c8f58d82cf730c` | PER_USER_INSTALL | `arp_version_hkcu` | PACKAGE_INVENTORY | SCCM export | HKCU hive not queried; user scope `current_user` not enumerated; provider `arp_user` not enumerated |
| `fx-da63098dbc5ef8b4` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | SCCM export | HKU hive not queried; user scope `other_user_loaded` not enumerated; provider `arp_user` not enumerated |
| `fx-832cb05b91aec9ad` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | SCCM export | HKU hive not queried; user scope `other_user_loaded` not enumerated; provider `arp_user` not enumerated |
| `fx-6b982ad56d8ea88a` | OFFLINE_OR_UNLOADED_USER_HIVE | `offline_hive_entry` | PACKAGE_INVENTORY | Tenable export | HKU hive not queried; user scope `other_user_offline` not enumerated |
| `fx-e6a1b4cd0faf1471` | OFFLINE_OR_UNLOADED_USER_HIVE | `offline_hive_entry` | PACKAGE_INVENTORY | Tenable export | HKU hive not queried; user scope `other_user_offline` not enumerated |
| `fx-8e578b8bb474c4d0` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | Tenable export | provider `appx` not enumerated |
| `fx-deb17a35d5976d29` | PARTIAL_DEVICE_OR_APPLICATION_SCOPE | `scoped_arp_entry` | PACKAGE_INVENTORY | Tenable export | provider `appx` not enumerated |
| `fx-da63098dbc5ef8b4` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | Tenable export | HKU hive not queried; user scope `other_user_loaded` not enumerated |
| `fx-832cb05b91aec9ad` | SECOND_LOCAL_USER_INSTALL | `arp_version_other_user` | PACKAGE_INVENTORY | Tenable export | HKU hive not queried; user scope `other_user_loaded` not enumerated |

## By collector

| Collector | Silent misses | Families affected |
| --- | --- | --- |
| A uninstall-registry | 8 | MACHINE_WIDE_WOW6432, PARTIAL_DEVICE_OR_APPLICATION_SCOPE, PER_USER_INSTALL, SECOND_LOCAL_USER_INSTALL |
| C package-provider | 4 | PARTIAL_DEVICE_OR_APPLICATION_SCOPE, SECOND_LOCAL_USER_INSTALL |
| Defender export | 2 | SECOND_LOCAL_USER_INSTALL |
| Intune export | 2 | SECOND_LOCAL_USER_INSTALL |
| SCCM export | 6 | PARTIAL_DEVICE_OR_APPLICATION_SCOPE, PER_USER_INSTALL, SECOND_LOCAL_USER_INSTALL |
| Tenable export | 6 | OFFLINE_OR_UNLOADED_USER_HIVE, PARTIAL_DEVICE_OR_APPLICATION_SCOPE, SECOND_LOCAL_USER_INSTALL |

## What survives the composite collector

None. The composite collector claims completeness for nothing, so by construction it cannot produce a silent miss: everything it fails to reach it reports as a declared gap.

That is a weaker statement than it looks, and it is worth being blunt about. It does not mean the composite sees everything. It means the composite is honest about what it does not see, which converts silent misses into abstentions. The cost shows up as 4/48 decisive facts left unresolved:

- **DISABLED_SERVICE_WITH_RESTART_MECHANISM** / `dependent_app_health` (APPLICATION_HEALTH) - RV3Lab_svc1 stopped, but a scheduled task restarts it. Classified `DECLARED_GAP`.
- **OFFLINE_OR_UNLOADED_USER_HIVE** / `offline_hive_entry` (PACKAGE_INVENTORY) - Northwind Agent registered in a user hive that is not currently loaded. Classified `DECLARED_GAP`.
- **OFFLINE_OR_UNLOADED_USER_HIVE** / `offline_hive_entry` (PACKAGE_INVENTORY) - Tailspin Viewer registered in a user hive that is not currently loaded. Classified `DECLARED_GAP`.
- **PARTIAL_DEVICE_OR_APPLICATION_SCOPE** / `scoped_app_health` (APPLICATION_HEALTH) - Contoso Reader present in an application scope the collector filters out. Classified `DECLARED_GAP`.

Two structural limits produce all of them. Reaching an unloaded user profile means `reg load` of NTUSER.DAT, which mutates the live registry namespace and is outside a read-only boundary - so a machine with a profile that has not signed in is not fully verifiable read-only. And no Windows inventory channel reports whether an application still works, so a functional regression is invisible to every collector here, including the composite.

