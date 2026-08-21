# Safety and lab procedure

This experiment may run against exactly one kind of machine: a disposable Windows VM you are prepared to destroy. Everything below exists to make any other outcome hard.

## What this run did

```text
========================================================================
  REMEDIATION VERIFICATION v3 - PREFLIGHT
========================================================================

  TARGET MACHINE
    hostname          vm
    platform          Linux 6.18.44-fc-v21
    os                unknown
    manufacturer      unknown
    model             unknown
    domain joined     None
    looks like a VM   None
    note              not Windows; VM detection and CIM identity are unavailable on this platform

  GATES
    ALLOW_WINDOWS_FIXTURE_SETUP    <unset>
    ALLOW_REAL_WINDOWS_LAB         <unset>
    RV3_LAB_CONFIRMATION           <unset>

  ACTIONS THAT WOULD BE PERFORMED
     1. CREATE 40 lab fixtures under C:\RV3Lab, HKLM/HKCU\SOFTWARE\RV3Lab, ARP keys prefixed RV3Lab_, services and scheduled tasks prefixed RV3Lab_, and disposable local accounts prefixed rv3lab_ (WRITES to this machine)
     2. RUN read-only collector A_UNINSTALL_REGISTRY
     3. RUN read-only collector B_EXPANDED_REGISTRY
     4. RUN read-only collector C_PACKAGE_PROVIDER
     5. RUN read-only collector D_FILE_VERSION
     6. RUN read-only collector E_SERVICE_TASK
     7. RUN read-only collector F_COMPOSITE_ACTIVE
     8. RUN read-only collector X_INTUNE_EXPORT
     9. RUN read-only collector X_DEFENDER_EXPORT
    10. RUN read-only collector X_TENABLE_EXPORT
    11. RUN read-only collector X_SCCM_EXPORT
    12. REMOVE every fixture created above (WRITES to this machine)
    13. WRITE collector output to the experiment's artifacts directory

  CONFIRMATION REQUIRED
    Set RV3_LAB_CONFIRMATION to this machine's own hostname ('vm') to confirm it is the disposable lab VM.
    Never run this against a host machine, a corporate endpoint, a production
    tenant, or any machine you are not prepared to discard.

  RESULT
    BLOCKED_NOT_EXECUTED - this is Linux, not Windows; no disposable Windows lab VM is reachable from this session

========================================================================
```

## The three gates

| Gate | Purpose | Effect if unset |
| --- | --- | --- |
| `ALLOW_REAL_WINDOWS_LAB=1` | permits running read-only collectors on a real machine | `GateNotSet` before any command is assembled |
| `ALLOW_WINDOWS_FIXTURE_SETUP=1` | permits creating or removing fixtures, the only writing path | `GateNotSet` before any command is assembled |
| `RV3_LAB_CONFIRMATION=<hostname>` | the operator naming the target machine | `ConfirmationMissing`, and a mismatch with the live hostname is also refused |

The third gate is deliberately not a boolean. A flag can be set by a stray environment file or an inherited shell; typing the name of the machine you are about to modify cannot be done by accident. Both the Python harness and the PowerShell scripts check all three independently, so bypassing one layer is not enough.

A non-Windows host is refused before the gates are even considered, which is what happened here.

## What may never be touched

- the host machine
- any corporate or managed endpoint
- a production tenant of any kind
- a live Intune, Configuration Manager, or Defender environment
- any machine not explicitly designated as the disposable lab

Vendor adapters are import-only. They read a file someone exported by hand; they do not authenticate, do not open a socket, and have no live-tenant code path.

## What the fixtures are made of

Nothing vulnerable is installed and no exploit is reproduced. A "vulnerable" fixture is a version string below a threshold, sitting at a particular coordinate in the evidence surface. The material is:

- copies of an existing benign system binary (`notepad.exe`) placed under `C:\RV3Lab`
- synthetic Add/Remove Programs entries prefixed `RV3Lab_`
- registry values under `SOFTWARE\RV3Lab`
- disposable services and scheduled tasks prefixed `RV3Lab_`
- disposable local accounts prefixed `rv3lab_`

The provisioning plan is 114 operations, hashed `875991010578a5731424dce9a2a500e4b7e796437b0bb13b508be5c0866de4be`.

## Win32_Product

Not used anywhere. Enumerating that WMI class triggers an MSI consistency check against every registered product on the machine, which can reconfigure software as a side effect of a supposedly read-only query. It is excluded by name in the collector contracts, in the PowerShell, and in the tests.

## Cleanup

`Remove-LabFixtures.ps1` cleans by prefix rather than by plan, so an interrupted or partially-applied provisioning run still cleans up completely. It drops the deny-ACE from the permission-denied fixture first, then removes tasks, services, local accounts, ARP keys, the lab registry namespace, and the lab directory, and reports any residue.

## Running it for real

```powershell
# On the disposable Windows VM only. Take a snapshot first.
$env:ALLOW_REAL_WINDOWS_LAB = '1'
$env:ALLOW_WINDOWS_FIXTURE_SETUP = '1'
$env:RV3_LAB_CONFIRMATION = $env:COMPUTERNAME
python run_experiment.py --preflight-only   # read this before going further
python run_experiment.py
```

Requirements: Windows 10/11 or Server 2019+, PowerShell 5.1 or later, Python 3.11+, local administrator (the composite collector and the permission-denied fixture need it), no network, and a snapshot taken beforehand. Expect the run to create a second local account and two scheduled tasks; both are removed by the cleanup script.

