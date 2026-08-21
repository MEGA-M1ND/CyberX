"""The collector contracts.

Six collectors are implemented in this repository (A-F); their contracts
describe what the PowerShell in `powershell/` actually queries, and can be
checked against the scripts.  Four optional import adapters (X_*) model vendor
export formats from published documentation and are marked as such - they are
the weakest evidence in this experiment and are reported separately.

Win32_Product appears nowhere.  Enumerating it triggers an MSI consistency check
against every registered product, which is a write-adjacent side effect and is
outside this experiment's read-only boundary.
"""
from __future__ import annotations

from typing import Dict, List

from ..vocab import CollectorId, EvidenceType, PackageProvider, PathRoot, RegistryView, UserScope
from .scope import IMPLEMENTED_HERE, VENDOR_DOC_MODEL, CollectorContract

E = EvidenceType
V = RegistryView
U = UserScope
P = PackageProvider
R = PathRoot

ALL_VIEWS = [V.VIEW_64.value, V.VIEW_32.value]
DEFAULT_FILE_ROOTS = [R.PROGRAM_FILES.value, R.PROGRAM_FILES_X86.value, R.PROGRAM_DATA.value]
ALL_FILE_ROOTS = [r.value for r in R]


A = CollectorContract(
    collector_id=CollectorId.A_UNINSTALL_REGISTRY.value,
    version="1.0.0",
    description="Standard uninstall-registry enumeration - the script every estate has",
    mechanism=r"Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (64-bit view)",
    basis=IMPLEMENTED_HERE,
    evidence_types=[E.PACKAGE_INVENTORY.value],
    registry_views=[V.VIEW_64.value],
    hives=["HKLM"],
    user_scopes=[U.MACHINE.value],
    providers=[P.ARP_MACHINE.value],
    # The point of this collector: it is universally consumed as "installed
    # software" and says nothing about the three scopes it never looks at.
    claims_complete_for=[E.PACKAGE_INVENTORY.value],
    declared_exclusions=[],
    approximate_seconds=0.8,
    approximate_records=180,
    notes="Represents the common field script. Claims a complete software inventory "
          "while reading one hive in one view.",
)

B = CollectorContract(
    collector_id=CollectorId.B_EXPANDED_REGISTRY.value,
    version="1.0.0",
    description="Expanded registry enumeration across both views and every loaded user hive",
    mechanism="RegistryKey.OpenBaseKey per view over HKLM and HKCU, plus enumeration of "
              "loaded HKU SIDs cross-referenced against ProfileList",
    basis=IMPLEMENTED_HERE,
    evidence_types=[E.PACKAGE_INVENTORY.value, E.REGISTRY_VALUE.value],
    registry_views=ALL_VIEWS,
    hives=["HKLM", "HKCU", "HKU"],
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value, U.OTHER_USER_LOADED.value],
    providers=[P.ARP_MACHINE.value, P.ARP_WOW6432.value, P.ARP_USER.value],
    # Enumerating ProfileList tells this collector which profiles exist but are
    # not loaded, so it can name what it is missing instead of implying zero.
    claims_complete_for=[],
    declared_exclusions=[U.OTHER_USER_OFFLINE.value, P.NONE_PORTABLE.value, P.APPX.value,
                         P.MSU_PACKAGE.value],
    approximate_seconds=3.5,
    approximate_records=420,
    notes="Same family of mechanism as A, with the exclusions written down. The "
          "difference in honesty costs about ten lines of PowerShell.",
)

C = CollectorContract(
    collector_id=CollectorId.C_PACKAGE_PROVIDER.value,
    version="1.0.0",
    description="PowerShell PackageManagement inventory (Programs provider)",
    mechanism="Get-Package -ProviderName Programs. Never Win32_Product.",
    basis=IMPLEMENTED_HERE,
    evidence_types=[E.PACKAGE_INVENTORY.value],
    registry_views=ALL_VIEWS,
    hives=["HKLM", "HKCU"],
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value],
    providers=[P.ARP_MACHINE.value, P.ARP_WOW6432.value, P.ARP_USER.value],
    claims_complete_for=[E.PACKAGE_INVENTORY.value],
    declared_exclusions=[],
    approximate_seconds=6.0,
    approximate_records=210,
    notes="Output is routinely treated as the software inventory, which is the "
          "completeness claim modelled here.",
)

D = CollectorContract(
    collector_id=CollectorId.D_FILE_VERSION.value,
    version="1.0.0",
    description="Targeted filesystem and file-version inspection",
    mechanism="Get-ChildItem over a declared root list, then FileVersionInfo per match",
    basis=IMPLEMENTED_HERE,
    evidence_types=[E.FILE_PRESENCE.value, E.FILE_VERSION.value],
    path_roots=list(DEFAULT_FILE_ROOTS),
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value, U.OTHER_USER_LOADED.value,
                 U.OTHER_USER_OFFLINE.value],
    claims_complete_for=[],
    declared_exclusions=[R.USER_PROFILE.value, R.APPDATA_LOCAL.value, R.NON_STANDARD.value],
    can_widen_scope_on_request=True,
    approximate_seconds=22.0,
    approximate_records=1400,
    notes="Cannot claim completeness by construction: it only knows about the roots "
          "it was given. That limitation is also what makes it honest.",
)

E_SVC = CollectorContract(
    collector_id=CollectorId.E_SERVICE_TASK.value,
    version="1.0.0",
    description="Service and scheduled-task inspection",
    mechanism="Get-Service plus Get-ScheduledTask / Get-ScheduledTaskInfo",
    basis=IMPLEMENTED_HERE,
    evidence_types=[E.SERVICE_STATE.value, E.SCHEDULED_TASK.value, E.PERSISTENCE_STATE.value],
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value],
    claims_complete_for=[E.SERVICE_STATE.value, E.SCHEDULED_TASK.value,
                         E.PERSISTENCE_STATE.value],
    declared_exclusions=[],
    approximate_seconds=4.5,
    approximate_records=310,
    notes="The one channel whose completeness claim its mechanism can actually "
          "support: both enumerations are genuinely exhaustive at machine scope.",
)

F = CollectorContract(
    collector_id=CollectorId.F_COMPOSITE_ACTIVE.value,
    version="1.0.0",
    description="Composite active collector: A-E plus bounded targeted follow-up",
    mechanism="Runs the registry, package, file and service channels, reconciles them, "
              "and re-queries widened file roots or specific hives when a decisive "
              "fact is unresolved",
    basis=IMPLEMENTED_HERE,
    evidence_types=[E.PACKAGE_INVENTORY.value, E.REGISTRY_VALUE.value, E.FILE_PRESENCE.value,
                    E.FILE_VERSION.value, E.SERVICE_STATE.value, E.SCHEDULED_TASK.value,
                    E.PERSISTENCE_STATE.value],
    registry_views=ALL_VIEWS,
    hives=["HKLM", "HKCU", "HKU"],
    # Deliberately NOT other_user_offline. Reaching an unloaded profile means
    # `reg load` of NTUSER.DAT, which mutates the live registry namespace and is
    # outside a read-only boundary. Two fixtures are therefore undecidable by any
    # collector in this experiment, and that is a finding rather than an omission.
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value, U.OTHER_USER_LOADED.value],
    path_roots=list(ALL_FILE_ROOTS),
    providers=[P.ARP_MACHINE.value, P.ARP_WOW6432.value, P.ARP_USER.value, P.APPX.value,
               P.MSU_PACKAGE.value, P.NONE_PORTABLE.value],
    claims_complete_for=[],
    declared_exclusions=[U.OTHER_USER_OFFLINE.value],
    requires_elevation=True,
    can_widen_scope_on_request=True,
    approximate_seconds=48.0,
    approximate_records=2100,
    notes="Union of the implemented channels. Claims nothing complete: it reports "
          "per-fact resolution and names what it could not settle.",
)

# ---- optional import-only adapters (offline exports; no live tenant) -------- #
X_INTUNE = CollectorContract(
    collector_id=CollectorId.X_INTUNE_EXPORT.value,
    version="0.1.0",
    description="Intune discovered-apps export (offline CSV/JSON only)",
    mechanism="Import of an exported discovered-applications report",
    basis=VENDOR_DOC_MODEL,
    evidence_types=[E.PACKAGE_INVENTORY.value],
    registry_views=ALL_VIEWS,
    hives=["HKLM", "HKCU"],
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value],
    providers=[P.ARP_MACHINE.value, P.ARP_WOW6432.value, P.ARP_USER.value, P.APPX.value],
    claims_complete_for=[E.PACKAGE_INVENTORY.value],
    emits_timestamps=True,
    approximate_seconds=0.2,
    approximate_records=260,
    notes="Presented to operators as the device's application inventory. No file "
          "version evidence and no arbitrary-path visibility.",
)

X_DEFENDER = CollectorContract(
    collector_id=CollectorId.X_DEFENDER_EXPORT.value,
    version="0.1.0",
    description="Defender Vulnerability Management software-inventory export (offline)",
    mechanism="Import of an exported software inventory / vulnerable-software report",
    basis=VENDOR_DOC_MODEL,
    evidence_types=[E.PACKAGE_INVENTORY.value, E.FILE_VERSION.value],
    registry_views=ALL_VIEWS,
    hives=["HKLM", "HKCU"],
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value],
    path_roots=[R.PROGRAM_FILES.value, R.PROGRAM_FILES_X86.value],
    providers=[P.ARP_MACHINE.value, P.ARP_WOW6432.value, P.ARP_USER.value, P.APPX.value],
    claims_complete_for=[E.PACKAGE_INVENTORY.value],
    approximate_seconds=0.2,
    approximate_records=300,
    notes="Broader than an ARP read, still product-recognition driven: an unrecognised "
          "or renamed binary outside a known product is not inventory.",
)

X_TENABLE = CollectorContract(
    collector_id=CollectorId.X_TENABLE_EXPORT.value,
    version="0.1.0",
    description="Tenable credentialed-scan export (offline)",
    mechanism="Import of an exported credentialed scan result",
    basis=VENDOR_DOC_MODEL,
    evidence_types=[E.PACKAGE_INVENTORY.value, E.REGISTRY_VALUE.value, E.FILE_VERSION.value],
    registry_views=ALL_VIEWS,
    hives=["HKLM", "HKCU"],
    user_scopes=[U.MACHINE.value, U.CURRENT_USER.value],
    path_roots=[R.PROGRAM_FILES.value, R.PROGRAM_FILES_X86.value, R.PROGRAM_DATA.value],
    providers=[P.ARP_MACHINE.value, P.ARP_WOW6432.value, P.ARP_USER.value],
    claims_complete_for=[E.PACKAGE_INVENTORY.value],
    requires_elevation=True,
    approximate_seconds=0.2,
    approximate_records=340,
    notes="Plugin-driven: checks the paths its plugins know about, which is wide but "
          "not arbitrary.",
)

X_SCCM = CollectorContract(
    collector_id=CollectorId.X_SCCM_EXPORT.value,
    version="0.1.0",
    description="Configuration Manager hardware/software inventory export (offline)",
    mechanism="Import of an exported inventory class report",
    basis=VENDOR_DOC_MODEL,
    evidence_types=[E.PACKAGE_INVENTORY.value, E.FILE_VERSION.value],
    registry_views=ALL_VIEWS,
    hives=["HKLM"],
    user_scopes=[U.MACHINE.value],
    path_roots=[R.PROGRAM_FILES.value, R.PROGRAM_FILES_X86.value],
    providers=[P.ARP_MACHINE.value, P.ARP_WOW6432.value],
    claims_complete_for=[E.PACKAGE_INVENTORY.value],
    approximate_seconds=0.2,
    approximate_records=280,
    notes="Software inventory is opt-in per file spec; per-user installs are absent "
          "from the default classes.",
)

IMPLEMENTED_CONTRACTS: List[CollectorContract] = [A, B, C, D, E_SVC, F]
IMPORT_CONTRACTS: List[CollectorContract] = [X_INTUNE, X_DEFENDER, X_TENABLE, X_SCCM]
ALL_CONTRACTS: List[CollectorContract] = IMPLEMENTED_CONTRACTS + IMPORT_CONTRACTS

BY_ID: Dict[str, CollectorContract] = {c.collector_id: c for c in ALL_CONTRACTS}


def contracts(include_imports: bool = True) -> List[CollectorContract]:
    return list(ALL_CONTRACTS) if include_imports else list(IMPLEMENTED_CONTRACTS)
