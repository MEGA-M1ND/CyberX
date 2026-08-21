"""Closed vocabularies for v3.  Data only - no decision logic lives here."""
from __future__ import annotations

import enum
from typing import List


class Mode(str, enum.Enum):
    DRY_RUN = "DRY_RUN"
    REAL_LAB = "REAL_LAB"


class RunStatus(str, enum.Enum):
    """What actually happened, recorded in every artefact."""

    PREDICTED_FROM_CONTRACTS = "PREDICTED_FROM_CONTRACTS"
    MEASURED_ON_LAB_VM = "MEASURED_ON_LAB_VM"
    BLOCKED_NOT_EXECUTED = "BLOCKED_NOT_EXECUTED"


class EvidenceType(str, enum.Enum):
    PACKAGE_INVENTORY = "PACKAGE_INVENTORY"
    REGISTRY_VALUE = "REGISTRY_VALUE"
    FILE_PRESENCE = "FILE_PRESENCE"
    FILE_VERSION = "FILE_VERSION"
    SERVICE_STATE = "SERVICE_STATE"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    PERSISTENCE_STATE = "PERSISTENCE_STATE"
    APPLICATION_HEALTH = "APPLICATION_HEALTH"


ALL_EVIDENCE_TYPES: List[str] = [e.value for e in EvidenceType]


class GapClass(str, enum.Enum):
    """Why a decisive fact did not reach the verifier.

    The distinction that matters is the first two.  A declared gap is one the
    collector's own contract predicts, so a scope-aware verifier can fail closed
    on it.  An undeclared gap is one the contract does not predict - the
    collector claimed the scope and did not deliver it - and v2 showed that no
    amount of manifest-reading defends against those.
    """

    NONE = "NONE"
    DECLARED_GAP = "DECLARED_GAP"
    UNDECLARED_GAP = "UNDECLARED_GAP"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    WRONG_DEVICE_OR_SCOPE = "WRONG_DEVICE_OR_SCOPE"
    COLLECTION_ERROR = "COLLECTION_ERROR"


ALL_GAP_CLASSES: List[str] = [g.value for g in GapClass]
SILENT_GAPS = frozenset({GapClass.UNDECLARED_GAP.value, GapClass.STALE_EVIDENCE.value,
                         GapClass.CONTRADICTORY_EVIDENCE.value,
                         GapClass.WRONG_DEVICE_OR_SCOPE.value})


class RegistryView(str, enum.Enum):
    VIEW_64 = "Registry64"
    VIEW_32 = "Registry32"


class UserScope(str, enum.Enum):
    MACHINE = "machine"
    CURRENT_USER = "current_user"
    OTHER_USER_LOADED = "other_user_loaded"
    OTHER_USER_OFFLINE = "other_user_offline"


class PathRoot(str, enum.Enum):
    """Real-world filesystem root classes a file collector may or may not scan.

    Lab fixtures live under a single disposable directory, but each decisive file
    fact records the root class it stands for, so a collector's declared root
    list is a meaningful claim rather than a formality.
    """

    PROGRAM_FILES = "ProgramFiles"
    PROGRAM_FILES_X86 = "ProgramFilesX86"
    PROGRAM_DATA = "ProgramData"
    USER_PROFILE = "UserProfile"
    APPDATA_LOCAL = "AppDataLocal"
    NON_STANDARD = "NonStandard"


class PackageProvider(str, enum.Enum):
    """Providers a package-inventory channel may enumerate.

    Win32_Product is deliberately absent: enumerating it triggers an MSI
    consistency check on every registered product, which is a write-adjacent
    side effect and is excluded by this experiment's safety boundary.
    """

    ARP_MACHINE = "arp_machine"
    ARP_WOW6432 = "arp_wow6432"
    ARP_USER = "arp_user"
    MSU_PACKAGE = "msu_package"
    APPX = "appx"
    NONE_PORTABLE = "none_portable"


class CollectorId(str, enum.Enum):
    A_UNINSTALL_REGISTRY = "A_UNINSTALL_REGISTRY"
    B_EXPANDED_REGISTRY = "B_EXPANDED_REGISTRY"
    C_PACKAGE_PROVIDER = "C_PACKAGE_PROVIDER"
    D_FILE_VERSION = "D_FILE_VERSION"
    E_SERVICE_TASK = "E_SERVICE_TASK"
    F_COMPOSITE_ACTIVE = "F_COMPOSITE_ACTIVE"
    X_INTUNE_EXPORT = "X_INTUNE_EXPORT"
    X_DEFENDER_EXPORT = "X_DEFENDER_EXPORT"
    X_TENABLE_EXPORT = "X_TENABLE_EXPORT"
    X_SCCM_EXPORT = "X_SCCM_EXPORT"


PASSIVE_COLLECTORS: List[str] = [
    CollectorId.A_UNINSTALL_REGISTRY.value,
    CollectorId.B_EXPANDED_REGISTRY.value,
    CollectorId.C_PACKAGE_PROVIDER.value,
    CollectorId.D_FILE_VERSION.value,
    CollectorId.E_SERVICE_TASK.value,
]
COMPOSITE_COLLECTOR = CollectorId.F_COMPOSITE_ACTIVE.value
OPTIONAL_IMPORT_COLLECTORS: List[str] = [
    CollectorId.X_INTUNE_EXPORT.value,
    CollectorId.X_DEFENDER_EXPORT.value,
    CollectorId.X_TENABLE_EXPORT.value,
    CollectorId.X_SCCM_EXPORT.value,
]

# The 20 fixture families the v3 brief requires.
FAMILIES: List[str] = [
    "MACHINE_WIDE_64BIT",
    "MACHINE_WIDE_WOW6432",
    "PER_USER_INSTALL",
    "SECOND_LOCAL_USER_INSTALL",
    "PORTABLE_UNREGISTERED",
    "SIDE_BY_SIDE_SAFE_AND_VULNERABLE",
    "BINARY_VERSION_DIFFERS_FROM_INVENTORY",
    "RENAMED_OR_NONDEFAULT_PATH",
    "RESIDUAL_BINARY_AFTER_UPDATE",
    "DISABLED_SERVICE_WITH_RESTART_MECHANISM",
    "SERVICE_STATE_DIFFERS_ACROSS_REBOOT",
    "SCHEDULED_TASK_RECREATES_COMPONENT",
    "REGISTRY_SPLIT_ACROSS_VIEWS_OR_HIVES",
    "OFFLINE_OR_UNLOADED_USER_HIVE",
    "PERMISSION_DENIED_EVIDENCE_PATH",
    "STALE_CACHED_INVENTORY",
    "PACKAGE_PRESENT_DECISIVE_FILE_MISSING",
    "PACKAGE_ABSENT_VULNERABLE_BINARY_PRESENT",
    "PARTIAL_DEVICE_OR_APPLICATION_SCOPE",
    "CONFLICTING_EVIDENCE_BETWEEN_COLLECTORS",
]

# Safety gates.  Both must be set for anything to touch a real machine.
GATE_FIXTURE_SETUP = "ALLOW_WINDOWS_FIXTURE_SETUP"
GATE_REAL_LAB = "ALLOW_REAL_WINDOWS_LAB"
GATE_CONFIRMATION = "RV3_LAB_CONFIRMATION"
