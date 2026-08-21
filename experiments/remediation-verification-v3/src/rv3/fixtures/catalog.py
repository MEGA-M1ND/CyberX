"""The 40-fixture catalog: two per required family.

Fixture ids are opaque digests.  The family name, the expectations, and the
decisive coordinates are ground truth; a collector receives only the id and the
lab roots to look under.

Every fixture is built from harmless material: copies of an existing benign
system binary under a dedicated lab root, synthetic Add/Remove Programs entries
under a lab prefix, registry values in a lab namespace, disposable services and
scheduled tasks, and (for the multi-user families) a disposable local account.
Nothing vulnerable is installed and no exploit is reproduced - "vulnerable"
here means a version string below a fixed threshold, at a location a collector
may or may not reach.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from ..vocab import EvidenceType, PackageProvider, PathRoot, RegistryView, UserScope
from .spec import (LAB_ARP_PREFIX, LAB_FILE_ROOT, LAB_REGISTRY_ROOT, LAB_SERVICE_PREFIX,
                   LAB_TASK_PREFIX, LAB_USER_PREFIX, PERSISTENCE, REGRESSION, VULNERABILITY,
                   Coordinates, DecisiveFact, FixtureSpec, SetupOp, validate)

E = EvidenceType
V = RegistryView
U = UserScope
P = PackageProvider
R = PathRoot

VULNERABLE_VERSION = "1.4.2"
FIXED_VERSION = "1.4.5"

PRODUCTS = [
    ("Contoso Reader", "contosoreader"),
    ("Fabrikam Sync", "fabrikamsync"),
    ("Northwind Agent", "northwindagent"),
    ("Tailspin Viewer", "tailspinviewer"),
]

# A benign, always-present system binary is copied to stand in for a product
# executable.  Its real FileVersion is recorded by the provisioner; the fixture
# only cares which *copy* is present at which path.
STUB_SOURCE = r"C:\Windows\System32\notepad.exe"

ARP_64 = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
ARP_32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"


def _fid(family: str, index: int) -> str:
    """Opaque fixture id.  Deliberately not derived from anything readable."""
    digest = hashlib.sha256(f"rv3|{family}|{index}".encode()).hexdigest()
    return f"fx-{digest[:16]}"


def _product(index: int) -> Dict[str, str]:
    name, slug = PRODUCTS[index % len(PRODUCTS)]
    return {"name": name, "slug": slug}


def _dir(*parts: str) -> str:
    return "\\".join([LAB_FILE_ROOT, *parts])


# --------------------------------------------------------------------------- #
# builders, one per family
# --------------------------------------------------------------------------- #
def _machine_wide_64bit(index: int) -> FixtureSpec:
    prod = _product(index)
    path = _dir("machine64", prod["slug"], f"{prod['slug']}.exe")
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}64"
    return FixtureSpec(
        fixture_id=_fid("MACHINE_WIDE_64BIT", index),
        family="MACHINE_WIDE_64BIT",
        title=f"{prod['name']} installed machine-wide, 64-bit registration",
        decisive_facts=[
            DecisiveFact("arp_version", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_64.value, hive="HKLM",
                                     user_scope=U.MACHINE.value, provider=P.ARP_MACHINE.value),
                         VULNERABILITY, note="the ordinary case every collector should handle"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("machine64", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_64.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": VULNERABLE_VERSION,
                                      "install_location": _dir("machine64", prod["slug"])}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKLM",
                                                      "view": V.VIEW_64.value})],
        notes="Control fixture: if a collector misses this, its contract is wrong.",
    )


def _machine_wide_wow6432(index: int) -> FixtureSpec:
    prod = _product(index + 1)
    path = _dir("machine32", prod["slug"], f"{prod['slug']}.exe")
    key = f"{ARP_32}\\{LAB_ARP_PREFIX}{prod['slug']}32"
    return FixtureSpec(
        fixture_id=_fid("MACHINE_WIDE_WOW6432", index),
        family="MACHINE_WIDE_WOW6432",
        title=f"{prod['name']} installed 32-bit, registered under WOW6432Node",
        decisive_facts=[
            DecisiveFact("arp_version_wow", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_32.value, hive="HKLM",
                                     user_scope=U.MACHINE.value, provider=P.ARP_WOW6432.value),
                         VULNERABILITY,
                         note="invisible to a 64-bit-view-only enumeration"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("machine32", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_32.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": VULNERABLE_VERSION,
                                      "install_location": _dir("machine32", prod["slug"])}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKLM",
                                                      "view": V.VIEW_32.value})],
    )


def _per_user_install(index: int) -> FixtureSpec:
    prod = _product(index + 2)
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}user"
    path = _dir("peruser", prod["slug"], f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("PER_USER_INSTALL", index),
        family="PER_USER_INSTALL",
        title=f"{prod['name']} installed for the current user only",
        decisive_facts=[
            DecisiveFact("arp_version_hkcu", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_64.value, hive="HKCU",
                                     user_scope=U.CURRENT_USER.value, provider=P.ARP_USER.value),
                         VULNERABILITY,
                         note="per-user installs are absent from every HKLM-only enumeration"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("peruser", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path}),
            SetupOp("new_arp_entry", {"hive": "HKCU", "view": V.VIEW_64.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": VULNERABLE_VERSION,
                                      "install_location": _dir("peruser", prod["slug"])}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKCU",
                                                      "view": V.VIEW_64.value})],
    )


def _second_local_user(index: int) -> FixtureSpec:
    prod = _product(index + 3)
    user = f"{LAB_USER_PREFIX}second{index}"
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}other"
    return FixtureSpec(
        fixture_id=_fid("SECOND_LOCAL_USER_INSTALL", index),
        family="SECOND_LOCAL_USER_INSTALL",
        title=f"{prod['name']} installed under a second local account",
        decisive_facts=[
            DecisiveFact("arp_version_other_user", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_64.value, hive="HKU",
                                     user_scope=U.OTHER_USER_LOADED.value,
                                     provider=P.ARP_USER.value),
                         VULNERABILITY,
                         note="reachable only by enumerating loaded HKU subkeys"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_local_user", {"name": user}),
            SetupOp("new_directory", {"path": _dir("otheruser", prod["slug"])}),
            SetupOp("new_arp_entry", {"hive": "HKU", "view": V.VIEW_64.value, "key": key,
                                      "user": user, "display_name": prod["name"],
                                      "display_version": VULNERABLE_VERSION}),
        ],
        cleanup_ops=[SetupOp("new_local_user", {"remove": user})],
    )


def _portable_unregistered(index: int) -> FixtureSpec:
    prod = _product(index)
    path = _dir("portable", f"{prod['slug']}-portable.exe")
    return FixtureSpec(
        fixture_id=_fid("PORTABLE_UNREGISTERED", index),
        family="PORTABLE_UNREGISTERED",
        title=f"{prod['name']} run as a portable executable, no installer registration",
        decisive_facts=[
            DecisiveFact("portable_binary_version", E.FILE_VERSION.value, path,
                         Coordinates(path_root=R.USER_PROFILE.value, provider=P.NONE_PORTABLE.value),
                         VULNERABILITY,
                         note="no package record exists anywhere; only the file speaks"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("portable")}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path,
                                          "label": VULNERABLE_VERSION}),
        ],
        cleanup_ops=[SetupOp("new_directory", {"remove": _dir("portable")})],
    )


def _side_by_side(index: int) -> FixtureSpec:
    prod = _product(index + 1)
    fixed_key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}fixed"
    vuln_path = _dir("sxs", prod["slug"], "v142", f"{prod['slug']}.exe")
    fixed_path = _dir("sxs", prod["slug"], "v145", f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("SIDE_BY_SIDE_SAFE_AND_VULNERABLE", index),
        family="SIDE_BY_SIDE_SAFE_AND_VULNERABLE",
        title=f"{prod['name']} {FIXED_VERSION} registered while {VULNERABLE_VERSION} remains on disk",
        decisive_facts=[
            DecisiveFact("residual_vuln_binary", E.FILE_VERSION.value, vuln_path,
                         Coordinates(path_root=R.PROGRAM_FILES.value, provider=P.NONE_PORTABLE.value),
                         VULNERABILITY,
                         note="the fixed ARP entry is true and irrelevant; this copy decides"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("sxs", prod["slug"], "v142")}),
            SetupOp("new_directory", {"path": _dir("sxs", prod["slug"], "v145")}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": vuln_path,
                                          "label": VULNERABLE_VERSION}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": fixed_path,
                                          "label": FIXED_VERSION}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_64.value, "key": fixed_key,
                                      "display_name": prod["name"],
                                      "display_version": FIXED_VERSION}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": fixed_key, "hive": "HKLM",
                                                      "view": V.VIEW_64.value})],
        notes="A package-inventory channel reads this as fully remediated.",
    )


def _binary_differs_from_inventory(index: int) -> FixtureSpec:
    prod = _product(index + 2)
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}bump"
    path = _dir("bumped", prod["slug"], f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("BINARY_VERSION_DIFFERS_FROM_INVENTORY", index),
        family="BINARY_VERSION_DIFFERS_FROM_INVENTORY",
        title=f"{prod['name']} ARP entry says {FIXED_VERSION}, the executable is still {VULNERABLE_VERSION}",
        decisive_facts=[
            DecisiveFact("actual_binary_version", E.FILE_VERSION.value, path,
                         Coordinates(path_root=R.PROGRAM_FILES.value),
                         VULNERABILITY,
                         note="an installer can bump the ARP entry without replacing the file"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("bumped", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path,
                                          "label": VULNERABLE_VERSION}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_64.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": FIXED_VERSION,
                                      "install_location": _dir("bumped", prod["slug"])}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKLM",
                                                      "view": V.VIEW_64.value})],
    )


def _renamed_nondefault_path(index: int) -> FixtureSpec:
    prod = _product(index + 3)
    path = _dir("odd", f"svc-helper-{index}.exe")
    return FixtureSpec(
        fixture_id=_fid("RENAMED_OR_NONDEFAULT_PATH", index),
        family="RENAMED_OR_NONDEFAULT_PATH",
        title=f"{prod['name']} executable renamed and moved outside its install location",
        decisive_facts=[
            DecisiveFact("renamed_binary_version", E.FILE_VERSION.value, path,
                         Coordinates(path_root=R.NON_STANDARD.value),
                         VULNERABILITY,
                         note="a path-list collector finds this only if the path is in its list"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("odd")}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path,
                                          "label": VULNERABLE_VERSION}),
        ],
        cleanup_ops=[SetupOp("new_directory", {"remove": _dir("odd")})],
    )


def _residual_after_update(index: int) -> FixtureSpec:
    prod = _product(index)
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}upd"
    residual = _dir("residual", prod["slug"], "old", f"{prod['slug']}.exe")
    current = _dir("residual", prod["slug"], "current", f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("RESIDUAL_BINARY_AFTER_UPDATE", index),
        family="RESIDUAL_BINARY_AFTER_UPDATE",
        title=f"{prod['name']} updated cleanly, old binary left behind in a sibling folder",
        decisive_facts=[
            DecisiveFact("residual_old_binary", E.FILE_VERSION.value, residual,
                         Coordinates(path_root=R.PROGRAM_FILES.value),
                         VULNERABILITY,
                         note="install_location points at 'current', not at the residue"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("residual", prod["slug"], "old")}),
            SetupOp("new_directory", {"path": _dir("residual", prod["slug"], "current")}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": residual,
                                          "label": VULNERABLE_VERSION}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": current,
                                          "label": FIXED_VERSION}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_64.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": FIXED_VERSION,
                                      "install_location": _dir("residual", prod["slug"], "current")}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKLM",
                                                      "view": V.VIEW_64.value})],
    )


def _disabled_service_with_restart(index: int) -> FixtureSpec:
    prod = _product(index + 1)
    service = f"{LAB_SERVICE_PREFIX}svc{index}"
    task = f"{LAB_TASK_PREFIX}restart{index}"
    binary = _dir("services", f"{prod['slug']}svc.exe")
    # Instance 1 additionally breaks a dependent application, so the corpus
    # contains regression fixtures and not only vulnerability fixtures.
    regression = index == 1
    regression_facts = [
        DecisiveFact("dependent_app_health", E.APPLICATION_HEALTH.value,
                     f"{prod['slug']}-client-starts",
                     Coordinates(user_scope=U.MACHINE.value),
                     REGRESSION,
                     note="stopping the service broke a dependent line-of-business client")
    ] if regression else []
    return FixtureSpec(
        fixture_id=_fid("DISABLED_SERVICE_WITH_RESTART_MECHANISM", index),
        family="DISABLED_SERVICE_WITH_RESTART_MECHANISM",
        title=f"{service} stopped, but a scheduled task restarts it",
        decisive_facts=[
            DecisiveFact("service_current_state", E.SERVICE_STATE.value, service,
                         Coordinates(user_scope=U.MACHINE.value),
                         VULNERABILITY),
            DecisiveFact("restart_task", E.SCHEDULED_TASK.value, task,
                         Coordinates(user_scope=U.MACHINE.value,
                                     requires_reboot_projection=True),
                         PERSISTENCE,
                         note="without the task, 'stopped' looks like remediation"),
            *regression_facts,
        ],
        expected_vulnerable=False, expected_persistent_after_reboot=False,
        expected_regression=regression,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("services")}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": binary}),
            SetupOp("new_service", {"name": service, "binary": binary,
                                    "startup": "Manual", "state": "Stopped"}),
            SetupOp("new_scheduled_task", {"name": task, "action": binary, "trigger": "AtStartup"}),
        ],
        cleanup_ops=[SetupOp("new_service", {"remove": service}),
                     SetupOp("new_scheduled_task", {"remove": task})],
        notes="Not vulnerable now; not persistent either. Both facts are needed.",
    )


def _service_state_across_reboot(index: int) -> FixtureSpec:
    service = f"{LAB_SERVICE_PREFIX}auto{index}"
    binary = _dir("services", f"auto{index}.exe")
    return FixtureSpec(
        fixture_id=_fid("SERVICE_STATE_DIFFERS_ACROSS_REBOOT", index),
        family="SERVICE_STATE_DIFFERS_ACROSS_REBOOT",
        title=f"{service} stopped now, startup type still Automatic",
        decisive_facts=[
            DecisiveFact("service_startup_type", E.PERSISTENCE_STATE.value, service,
                         Coordinates(user_scope=U.MACHINE.value,
                                     requires_reboot_projection=True),
                         PERSISTENCE,
                         note="current state says stopped; startup type says it comes back"),
        ],
        expected_vulnerable=False, expected_persistent_after_reboot=False, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("services")}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": binary}),
            SetupOp("new_service", {"name": service, "binary": binary,
                                    "startup": "Automatic", "state": "Stopped"}),
        ],
        cleanup_ops=[SetupOp("new_service", {"remove": service})],
    )


def _scheduled_task_recreates(index: int) -> FixtureSpec:
    task = f"{LAB_TASK_PREFIX}recreate{index}"
    target = _dir("recreated", f"component{index}.exe")
    return FixtureSpec(
        fixture_id=_fid("SCHEDULED_TASK_RECREATES_COMPONENT", index),
        family="SCHEDULED_TASK_RECREATES_COMPONENT",
        title=f"A scheduled task re-deploys a removed component at logon",
        decisive_facts=[
            DecisiveFact("recreate_task", E.SCHEDULED_TASK.value, task,
                         Coordinates(user_scope=U.MACHINE.value,
                                     requires_reboot_projection=True),
                         PERSISTENCE,
                         note="the file is gone now and will be back after logon"),
        ],
        expected_vulnerable=False, expected_persistent_after_reboot=False, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("recreated")}),
            SetupOp("new_scheduled_task", {"name": task, "action": target, "trigger": "AtLogon"}),
        ],
        cleanup_ops=[SetupOp("new_scheduled_task", {"remove": task})],
    )


def _registry_split(index: int) -> FixtureSpec:
    native = f"{LAB_REGISTRY_ROOT}\\Policy{index}\\Enabled"
    wow = f"SOFTWARE\\WOW6432Node\\RV3Lab\\Policy{index}\\Enabled"
    return FixtureSpec(
        fixture_id=_fid("REGISTRY_SPLIT_ACROSS_VIEWS_OR_HIVES", index),
        family="REGISTRY_SPLIT_ACROSS_VIEWS_OR_HIVES",
        title="Mitigation written to the 64-bit view; the effective value lives in the 32-bit view",
        decisive_facts=[
            DecisiveFact("wow_policy_value", E.REGISTRY_VALUE.value, wow,
                         Coordinates(registry_view=V.VIEW_32.value, hive="HKLM",
                                     user_scope=U.MACHINE.value),
                         VULNERABILITY,
                         note="a 64-bit-view read returns the secure value and misses this one"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("write_registry_value", {"hive": "HKLM", "view": V.VIEW_64.value,
                                             "key": native, "value": 1}),
            SetupOp("write_registry_value", {"hive": "HKLM", "view": V.VIEW_32.value,
                                             "key": wow, "value": 0}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": f"{LAB_REGISTRY_ROOT}\\Policy{index}",
                                                      "hive": "HKLM", "view": V.VIEW_64.value}),
                     SetupOp("write_registry_value", {"delete_key": f"SOFTWARE\\WOW6432Node\\RV3Lab\\Policy{index}",
                                                      "hive": "HKLM", "view": V.VIEW_32.value})],
    )


def _offline_user_hive(index: int) -> FixtureSpec:
    prod = _product(index + 2)
    user = f"{LAB_USER_PREFIX}offline{index}"
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}offline"
    return FixtureSpec(
        fixture_id=_fid("OFFLINE_OR_UNLOADED_USER_HIVE", index),
        family="OFFLINE_OR_UNLOADED_USER_HIVE",
        title=f"{prod['name']} registered in a user hive that is not currently loaded",
        decisive_facts=[
            DecisiveFact("offline_hive_entry", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_64.value, hive="HKU",
                                     user_scope=U.OTHER_USER_OFFLINE.value,
                                     provider=P.ARP_USER.value, requires_elevated_read=True),
                         VULNERABILITY,
                         note="requires mounting NTUSER.DAT; no live enumeration reaches it"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_local_user", {"name": user}),
            SetupOp("new_arp_entry", {"hive": "HKU", "view": V.VIEW_64.value, "key": key,
                                      "user": user, "display_name": prod["name"],
                                      "display_version": VULNERABLE_VERSION}),
            SetupOp("unload_user_hive", {"user": user}),
        ],
        cleanup_ops=[SetupOp("new_local_user", {"remove": user})],
    )


def _permission_denied(index: int) -> FixtureSpec:
    prod = _product(index + 3)
    path = _dir("restricted", prod["slug"], f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("PERMISSION_DENIED_EVIDENCE_PATH", index),
        family="PERMISSION_DENIED_EVIDENCE_PATH",
        title=f"{prod['name']} binary sits in a directory the collector cannot read",
        decisive_facts=[
            DecisiveFact("restricted_binary_version", E.FILE_VERSION.value, path,
                         Coordinates(path_root=R.PROGRAM_DATA.value, requires_elevated_read=True),
                         VULNERABILITY,
                         note="the honest outcome is a declared collection error, not silence"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("restricted", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path,
                                          "label": VULNERABLE_VERSION}),
            SetupOp("deny_read_acl", {"path": _dir("restricted", prod["slug"])}),
        ],
        cleanup_ops=[SetupOp("deny_read_acl", {"remove": _dir("restricted", prod["slug"])})],
        notes="Tests whether a collector reports the failure or silently returns nothing.",
    )


def _stale_cached_inventory(index: int) -> FixtureSpec:
    prod = _product(index)
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}stale"
    return FixtureSpec(
        fixture_id=_fid("STALE_CACHED_INVENTORY", index),
        family="STALE_CACHED_INVENTORY",
        title=f"{prod['name']} removed after the last inventory cycle; the cache still lists it",
        decisive_facts=[
            DecisiveFact("live_arp_state", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_64.value, hive="HKLM",
                                     user_scope=U.MACHINE.value, provider=P.ARP_MACHINE.value),
                         VULNERABILITY, freshness_sensitive=True,
                         note="a cached answer is wrong in the safe direction here, and wrong"),
        ],
        expected_vulnerable=False, expected_persistent_after_reboot=False, expected_regression=False,
        setup_ops=[
            SetupOp("touch_inventory_cache", {"key": key, "display_name": prod["name"],
                                              "display_version": VULNERABLE_VERSION,
                                              "age_hours": 72}),
        ],
        cleanup_ops=[SetupOp("touch_inventory_cache", {"remove": key})],
    )


def _package_present_file_missing(index: int) -> FixtureSpec:
    prod = _product(index + 1)
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}nofile"
    path = _dir("nofile", prod["slug"], f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("PACKAGE_PRESENT_DECISIVE_FILE_MISSING", index),
        family="PACKAGE_PRESENT_DECISIVE_FILE_MISSING",
        title=f"{prod['name']} is registered but its executable is gone",
        decisive_facts=[
            DecisiveFact("missing_binary", E.FILE_PRESENCE.value, path,
                         Coordinates(path_root=R.PROGRAM_FILES.value),
                         VULNERABILITY,
                         note="the package record alone cannot tell you the code is absent"),
        ],
        expected_vulnerable=False, expected_persistent_after_reboot=False, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("nofile", prod["slug"])}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_64.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": VULNERABLE_VERSION,
                                      "install_location": _dir("nofile", prod["slug"])}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKLM",
                                                      "view": V.VIEW_64.value})],
        notes="Inverse of the usual error: inventory over-reports risk here.",
    )


def _package_absent_binary_present(index: int) -> FixtureSpec:
    prod = _product(index + 2)
    path = _dir("unregistered", prod["slug"], f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("PACKAGE_ABSENT_VULNERABLE_BINARY_PRESENT", index),
        family="PACKAGE_ABSENT_VULNERABLE_BINARY_PRESENT",
        title=f"{prod['name']} uninstalled cleanly, vulnerable executable still on disk",
        decisive_facts=[
            DecisiveFact("orphan_binary_version", E.FILE_VERSION.value, path,
                         Coordinates(path_root=R.APPDATA_LOCAL.value, provider=P.NONE_PORTABLE.value),
                         VULNERABILITY,
                         note="every package channel correctly reports nothing installed"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("unregistered", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path,
                                          "label": VULNERABLE_VERSION}),
        ],
        cleanup_ops=[SetupOp("new_directory", {"remove": _dir("unregistered", prod["slug"])})],
    )


def _partial_scope(index: int) -> FixtureSpec:
    prod = _product(index + 3)
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}scope"
    path = _dir("scoped", prod["slug"], f"{prod['slug']}.exe")
    regression = index == 1
    regression_facts = [
        DecisiveFact("scoped_app_health", E.APPLICATION_HEALTH.value,
                     f"{prod['slug']}-addin-loads",
                     Coordinates(user_scope=U.CURRENT_USER.value),
                     REGRESSION,
                     note="the scoped package's add-in no longer loads after the change")
    ] if regression else []
    return FixtureSpec(
        fixture_id=_fid("PARTIAL_DEVICE_OR_APPLICATION_SCOPE", index),
        family="PARTIAL_DEVICE_OR_APPLICATION_SCOPE",
        title=f"{prod['name']} present in an application scope the collector filters out",
        decisive_facts=[
            DecisiveFact("scoped_arp_entry", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_64.value, hive="HKLM",
                                     user_scope=U.MACHINE.value, provider=P.APPX.value),
                         VULNERABILITY,
                         note="an ARP-only provider list never enumerates this package type"),
            DecisiveFact("scoped_binary", E.FILE_VERSION.value, path,
                         Coordinates(path_root=R.PROGRAM_FILES.value),
                         VULNERABILITY),
            *regression_facts,
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True,
        expected_regression=regression,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("scoped", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path,
                                          "label": VULNERABLE_VERSION}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_64.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": VULNERABLE_VERSION,
                                      "package_kind": "appx"}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKLM",
                                                      "view": V.VIEW_64.value})],
    )


def _conflicting_evidence(index: int) -> FixtureSpec:
    prod = _product(index)
    key = f"{ARP_64}\\{LAB_ARP_PREFIX}{prod['slug']}conflict"
    path = _dir("conflict", prod["slug"], f"{prod['slug']}.exe")
    return FixtureSpec(
        fixture_id=_fid("CONFLICTING_EVIDENCE_BETWEEN_COLLECTORS", index),
        family="CONFLICTING_EVIDENCE_BETWEEN_COLLECTORS",
        title=f"{prod['name']} ARP entry and file version disagree about which build is installed",
        decisive_facts=[
            DecisiveFact("conflict_arp", E.PACKAGE_INVENTORY.value, key,
                         Coordinates(registry_view=V.VIEW_64.value, hive="HKLM",
                                     user_scope=U.MACHINE.value, provider=P.ARP_MACHINE.value),
                         VULNERABILITY),
            DecisiveFact("conflict_file", E.FILE_VERSION.value, path,
                         Coordinates(path_root=R.PROGRAM_FILES.value),
                         VULNERABILITY,
                         note="two channels, two answers; the disagreement is the signal"),
        ],
        expected_vulnerable=True, expected_persistent_after_reboot=True, expected_regression=False,
        setup_ops=[
            SetupOp("new_directory", {"path": _dir("conflict", prod["slug"])}),
            SetupOp("place_stub_binary", {"source": STUB_SOURCE, "dest": path,
                                          "label": VULNERABLE_VERSION}),
            SetupOp("new_arp_entry", {"hive": "HKLM", "view": V.VIEW_64.value, "key": key,
                                      "display_name": prod["name"],
                                      "display_version": FIXED_VERSION,
                                      "install_location": _dir("conflict", prod["slug"])}),
        ],
        cleanup_ops=[SetupOp("write_registry_value", {"delete_key": key, "hive": "HKLM",
                                                      "view": V.VIEW_64.value})],
    )


BUILDERS = {
    "MACHINE_WIDE_64BIT": _machine_wide_64bit,
    "MACHINE_WIDE_WOW6432": _machine_wide_wow6432,
    "PER_USER_INSTALL": _per_user_install,
    "SECOND_LOCAL_USER_INSTALL": _second_local_user,
    "PORTABLE_UNREGISTERED": _portable_unregistered,
    "SIDE_BY_SIDE_SAFE_AND_VULNERABLE": _side_by_side,
    "BINARY_VERSION_DIFFERS_FROM_INVENTORY": _binary_differs_from_inventory,
    "RENAMED_OR_NONDEFAULT_PATH": _renamed_nondefault_path,
    "RESIDUAL_BINARY_AFTER_UPDATE": _residual_after_update,
    "DISABLED_SERVICE_WITH_RESTART_MECHANISM": _disabled_service_with_restart,
    "SERVICE_STATE_DIFFERS_ACROSS_REBOOT": _service_state_across_reboot,
    "SCHEDULED_TASK_RECREATES_COMPONENT": _scheduled_task_recreates,
    "REGISTRY_SPLIT_ACROSS_VIEWS_OR_HIVES": _registry_split,
    "OFFLINE_OR_UNLOADED_USER_HIVE": _offline_user_hive,
    "PERMISSION_DENIED_EVIDENCE_PATH": _permission_denied,
    "STALE_CACHED_INVENTORY": _stale_cached_inventory,
    "PACKAGE_PRESENT_DECISIVE_FILE_MISSING": _package_present_file_missing,
    "PACKAGE_ABSENT_VULNERABLE_BINARY_PRESENT": _package_absent_binary_present,
    "PARTIAL_DEVICE_OR_APPLICATION_SCOPE": _partial_scope,
    "CONFLICTING_EVIDENCE_BETWEEN_COLLECTORS": _conflicting_evidence,
}

INSTANCES_PER_FAMILY = 2


def build_catalog() -> List[FixtureSpec]:
    from ..vocab import FAMILIES
    out: List[FixtureSpec] = []
    for family in FAMILIES:
        builder = BUILDERS[family]
        for index in range(INSTANCES_PER_FAMILY):
            spec = builder(index)
            validate(spec)
            out.append(spec)
    return out


def catalog_summary() -> Dict[str, Any]:
    catalog = build_catalog()
    return {
        "fixtures": len(catalog),
        "families": len({f.family for f in catalog}),
        "decisive_facts": sum(len(f.decisive_facts) for f in catalog),
        "vulnerable_fixtures": sum(1 for f in catalog if f.expected_vulnerable),
        "safe_fixtures": sum(1 for f in catalog if not f.expected_vulnerable),
    }
