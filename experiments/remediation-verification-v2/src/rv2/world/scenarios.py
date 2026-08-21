"""Base scenario families.

Each family is a *latent* construction: baseline state, what the remediation
really did, whether a reboot happened, and what the delivery tool reported.  No
family declares its own verdict - the oracle derives that from the resulting
world.  That is what lets 13 families times 25 evidence conditions be generated
rather than hand-labelled.

Each family also declares a `decisive_hint`: the single evidence field that, if
hidden, most changes what an observer can conclude.  The hint is used by the
evidence-condition generator and by the decision-relevance measurement.  It is
never placed in an observation package.
"""
from __future__ import annotations

import random
from typing import Any, Callable, Dict, List, Tuple

from .risk_library import RISK_FLAGS
from .state import (
    T_BASELINE,
    T_COLLECTION,
    T_REBOOT,
    T_REMEDIATION,
    DeviceState,
    ExecutionReport,
    InstalledPackage,
    LatentDevice,
    LatentWorld,
    Snapshot,
    project_reboot,
)

PRODUCTS: List[Tuple[str, str, str]] = [
    ("AcmeReader", "1.4.2", "1.4.5"),
    ("NimbusSync", "3.2.1", "3.3.0"),
    ("OrionAgent", "7.0.4", "7.1.2"),
    ("VertexPDF", "11.5.0", "11.6.1"),
]

POLICY_KEYS: List[Tuple[str, Any, Any]] = [
    ("HKLM\\SOFTWARE\\Policies\\Acme\\Office\\BlockMacrosFromInternet", 0, 1),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1", 1, 0),
    ("HKLM\\SOFTWARE\\Policies\\Nimbus\\Client\\RequireSignedUpdates", 0, 1),
]

WOW_KEYS: List[Tuple[str, Any, Any]] = [
    ("HKLM\\SOFTWARE\\WOW6432Node\\Policies\\Acme\\Office\\BlockMacrosFromInternet", 0, 1),
    ("HKLM\\SOFTWARE\\WOW6432Node\\Vertex\\LegacyAuthEnabled", 1, 0),
]

SERVICES = ["AcmeListener", "NimbusRelay", "OrionCollector"]
HEALTH_POOL = ["lob_app_starts", "endpoint_agent_healthy", "vpn_client_connects",
               "print_service_healthy", "directory_sync_ok"]

KB_SECURITY = ["KB5031234", "KB5033111", "KB5036002"]
KB_SERVICING = ["KB5040001", "KB5041777"]

FAMILIES = [
    "GENUINE_REMEDIATION",
    "EXIT_ZERO_NO_CHANGE",
    "WRONG_REGISTRY_KEY",
    "WRONG_PRODUCT_IDENTITY",
    "SIDE_BY_SIDE_VULNERABLE",
    "PARTIAL_MULTI_PREDICATE",
    "SERVICE_RETURNS_AFTER_REBOOT",
    "REBOOT_REQUIRED_NOT_PERFORMED",
    "VULNERABLE_BINARY_ON_DISK",
    "INVENTORY_UPDATED_BINARY_UNCHANGED",
    "GROUP_PARTIAL_ROLLOUT",
    "REGRESSION_INTRODUCED",
    "NEW_EXPOSURE_INTRODUCED",
]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _base_state(rng: random.Random, health: List[str]) -> DeviceState:
    return DeviceState(
        application_health={name: True for name in health},
        security_posture={flag: False for flag in RISK_FLAGS},
    )


def _timeline(baseline: DeviceState, mutate: Callable[[DeviceState], None],
              reboot_performed: bool) -> List[Snapshot]:
    post = baseline.clone()
    mutate(post)
    snaps = [Snapshot(T_BASELINE, "baseline", baseline),
             Snapshot(T_REMEDIATION, "post_remediation", post)]
    if reboot_performed:
        snaps.append(Snapshot(T_REBOOT, "post_reboot", project_reboot(post)))
    return snaps


def _device(device_id: str, baseline: DeviceState, mutate: Callable[[DeviceState], None],
            reboot_performed: bool, enumerable: bool = True) -> LatentDevice:
    return LatentDevice(device_id=device_id, timeline=_timeline(baseline, mutate, reboot_performed),
                        enumerable=enumerable)


def _health(rng: random.Random, n: int = 2) -> List[str]:
    return sorted(rng.sample(HEALTH_POOL, n))


def _world(case_id: str, family: str, devices: List[LatentDevice], targeted: List[str],
           execution: ExecutionReport, reboot_performed: bool, predicate: Dict[str, Any],
           intent: Dict[str, Any], health: List[str], hint: Dict[str, Any]) -> LatentWorld:
    return LatentWorld(
        case_id=case_id, family=family, devices=devices, targeted_device_ids=targeted,
        execution=execution, reboot_performed=reboot_performed,
        vulnerability_predicate=predicate, remediation_intent=intent,
        required_health_checks=health, decisive_hint=hint, collected_at=T_COLLECTION,
    )


def _ok(devices: int = 1, exit_code: int = 0, status: str = "Succeeded",
        reported: int = None) -> ExecutionReport:
    return ExecutionReport(exit_code=exit_code, execution_status=status,
                           deployment_status=status, devices_targeted=devices,
                           devices_reported_success=devices if reported is None else reported)


# --------------------------------------------------------------------------- #
# families
# --------------------------------------------------------------------------- #
def genuine_remediation(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    health = _health(rng)
    base = _base_state(rng, health)
    base.packages = [InstalledPackage(name, vuln_v, "machine", f"{{{name}-M}}")]

    def mutate(s: DeviceState) -> None:
        s.packages = [InstalledPackage(name, fixed_v, "machine", f"{{{name}-M}}")]

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "GENUINE_REMEDIATION", [dev], ["device-001"], _ok(1), False,
        {"id": "PKG_BELOW_FIX", "op": "package_version_below", "package": name, "fixed_version": fixed_v},
        {"description": f"Upgrade {name} to {fixed_v} and remove the vulnerable build",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v},
             {"id": "VULN_ABSENT", "op": "package_absent", "package": name, "version": vuln_v}]},
        health,
        {"evidence_type": "PACKAGE_INVENTORY", "device_id": "device-001",
         "scope_key": "machine", "note": "the inventory entry proving the fixed build is installed"},
    )


def exit_zero_no_change(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    health = _health(rng)
    base = _base_state(rng, health)
    base.packages = [InstalledPackage(name, vuln_v, "machine", f"{{{name}-M}}")]
    dev = _device("device-001", base, lambda s: None, reboot_performed=False)
    return _world(
        case_id, "EXIT_ZERO_NO_CHANGE", [dev], ["device-001"],
        _ok(1), False,
        {"id": "PKG_BELOW_FIX", "op": "package_version_below", "package": name, "fixed_version": fixed_v},
        {"description": f"Upgrade {name} to {fixed_v}",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v}]},
        health,
        {"evidence_type": "PACKAGE_INVENTORY", "device_id": "device-001",
         "scope_key": "machine", "note": "the still-vulnerable inventory entry"},
    )


def wrong_registry_key(rng: random.Random, case_id: str) -> LatentWorld:
    wow_path, wow_insecure, wow_secure = rng.choice(WOW_KEYS)
    native_path, native_insecure, native_secure = rng.choice(POLICY_KEYS)
    health = _health(rng)
    base = _base_state(rng, health)
    base.registry = {wow_path: wow_insecure, native_path: native_insecure}

    def mutate(s: DeviceState) -> None:
        s.registry[native_path] = native_secure  # the script hardened the wrong hive

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "WRONG_REGISTRY_KEY", [dev], ["device-001"], _ok(1), False,
        {"id": "WOW_KEY_INSECURE", "op": "registry_not_equals", "path": wow_path, "value": wow_secure},
        {"description": "Apply the policy value that disables the vulnerable behaviour",
         "target_state_assertions": [
             {"id": "NATIVE_KEY_SET", "op": "registry_equals", "path": native_path, "value": native_secure}]},
        health,
        {"evidence_type": "REGISTRY_STATE", "device_id": "device-001",
         "scope_key": "HKLM\\SOFTWARE\\WOW6432Node",
         "note": "the 32-bit hive key that is actually vulnerable"},
    )


def wrong_product_identity(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    enterprise = f"{name} Enterprise"
    health = _health(rng)
    base = _base_state(rng, health)
    base.packages = [InstalledPackage(name, vuln_v, "machine", f"{{{name}-M}}"),
                     InstalledPackage(enterprise, vuln_v, "machine", f"{{{name}-ENT}}")]

    def mutate(s: DeviceState) -> None:
        s.packages = [InstalledPackage(name, fixed_v, "machine", f"{{{name}-M}}"),
                      InstalledPackage(enterprise, vuln_v, "machine", f"{{{name}-ENT}}")]

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "WRONG_PRODUCT_IDENTITY", [dev], ["device-001"], _ok(1), False,
        {"id": "ENT_BELOW_FIX", "op": "package_version_below", "package": enterprise, "fixed_version": fixed_v},
        {"description": f"Upgrade {name} to {fixed_v}",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v}]},
        health,
        {"evidence_type": "PACKAGE_INVENTORY", "device_id": "device-001",
         "scope_key": "machine", "note": "the Enterprise edition entry that was never patched"},
    )


def side_by_side_vulnerable(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    health = _health(rng)
    base = _base_state(rng, health)
    base.packages = [InstalledPackage(name, vuln_v, "per_user", f"{{{name}-U}}")]

    def mutate(s: DeviceState) -> None:
        s.packages = [InstalledPackage(name, vuln_v, "per_user", f"{{{name}-U}}"),
                      InstalledPackage(name, fixed_v, "machine", f"{{{name}-M}}")]

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "SIDE_BY_SIDE_VULNERABLE", [dev], ["device-001"], _ok(1), False,
        {"id": "PKG_BELOW_FIX", "op": "package_version_below", "package": name, "fixed_version": fixed_v},
        {"description": f"Install {name} {fixed_v}",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v}]},
        health,
        {"evidence_type": "PACKAGE_INVENTORY", "device_id": "device-001",
         "scope_key": "per_user", "note": "the per-user install still on the vulnerable build"},
    )


def partial_multi_predicate(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    path, insecure, secure = rng.choice(POLICY_KEYS)
    health = _health(rng)
    base = _base_state(rng, health)
    base.packages = [InstalledPackage(name, vuln_v, "machine", f"{{{name}-M}}")]
    base.registry = {path: insecure}

    def mutate(s: DeviceState) -> None:
        s.packages = [InstalledPackage(name, fixed_v, "machine", f"{{{name}-M}}")]
        # the registry half of the mitigation is never applied

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "PARTIAL_MULTI_PREDICATE", [dev], ["device-001"], _ok(1), False,
        {"op": "any_of", "operands": [
            {"id": "PKG_BELOW_FIX", "op": "package_version_below", "package": name, "fixed_version": fixed_v},
            {"id": "POLICY_INSECURE", "op": "registry_not_equals", "path": path, "value": secure}]},
        {"description": f"Upgrade {name} and apply the accompanying policy",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v}]},
        health,
        {"evidence_type": "REGISTRY_STATE", "device_id": "device-001",
         "scope_key": _registry_root(path), "note": "the unapplied second half of the mitigation"},
    )


def service_returns_after_reboot(rng: random.Random, case_id: str) -> LatentWorld:
    service = rng.choice(SERVICES)
    health = _health(rng)
    base = _base_state(rng, health)
    base.services = {service: {"status": "running", "startup_type": "automatic"}}

    def mutate(s: DeviceState) -> None:
        s.services[service]["status"] = "stopped"  # startup type left automatic

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "SERVICE_RETURNS_AFTER_REBOOT", [dev], ["device-001"], _ok(1), False,
        {"id": "SERVICE_RUNNING", "op": "service_running", "service": service},
        {"description": f"Stop the {service} listener",
         "target_state_assertions": [
             {"id": "SERVICE_STOPPED", "op": "service_stopped", "service": service}]},
        health,
        {"evidence_type": "SERVICE_STATE", "device_id": "device-001",
         "scope_key": "automatic", "note": "the startup type showing the service comes back"},
    )


def reboot_required_not_performed(rng: random.Random, case_id: str) -> LatentWorld:
    kb = rng.choice(KB_SERVICING)
    health = _health(rng)
    base = _base_state(rng, health)
    base.patches = {kb: {"installed": False, "staged": False}}

    def mutate(s: DeviceState) -> None:
        s.patches[kb] = {"installed": False, "staged": True}
        s.reboot_pending = True

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "REBOOT_REQUIRED_NOT_PERFORMED", [dev], ["device-001"],
        _ok(1, status="Compliant"), False,
        {"id": "KB_MISSING", "op": "patch_missing", "kb": kb},
        {"description": f"Install {kb}",
         "target_state_assertions": [
             {"id": "KB_APPLIED", "op": "any_of", "operands": [
                 {"op": "patch_installed", "kb": kb}, {"op": "patch_staged", "kb": kb}]}]},
        health,
        {"evidence_type": "PATCH_STATE", "device_id": "device-001",
         "scope_key": "servicing_stack", "note": "the staged-but-not-installed patch record"},
    )


def vulnerable_binary_on_disk(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    legacy = f"C:\\Program Files (x86)\\{name}\\legacy\\{name.lower()}.exe"
    current = f"C:\\Program Files\\{name}\\{name.lower()}.exe"
    health = _health(rng)
    base = _base_state(rng, health)
    base.files = {legacy: {"exists": True, "version": vuln_v},
                  current: {"exists": True, "version": vuln_v}}

    def mutate(s: DeviceState) -> None:
        s.files[current] = {"exists": True, "version": fixed_v}

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "VULNERABLE_BINARY_ON_DISK", [dev], ["device-001"], _ok(1), False,
        {"id": "LEGACY_BIN_VULNERABLE", "op": "file_version_below", "path": legacy, "fixed_version": fixed_v},
        {"description": f"Deploy {name} {fixed_v} to the current install path",
         "target_state_assertions": [
             {"id": "CURRENT_BIN_PRESENT", "op": "file_present", "path": current}]},
        health,
        {"evidence_type": "FILE_STATE", "device_id": "device-001",
         "scope_key": "C:\\Program Files (x86)", "note": "the vulnerable binary left in the x86 tree"},
    )


def inventory_updated_binary_unchanged(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    binary = f"C:\\Program Files\\{name}\\{name.lower()}.exe"
    health = _health(rng)
    base = _base_state(rng, health)
    base.packages = [InstalledPackage(name, vuln_v, "machine", f"{{{name}-M}}")]
    base.files = {binary: {"exists": True, "version": vuln_v}}

    def mutate(s: DeviceState) -> None:
        # the installer bumps the ARP entry but the executable is never replaced
        s.packages = [InstalledPackage(name, fixed_v, "machine", f"{{{name}-M}}")]

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "INVENTORY_UPDATED_BINARY_UNCHANGED", [dev], ["device-001"], _ok(1), False,
        {"id": "BIN_BELOW_FIX", "op": "file_version_below", "path": binary, "fixed_version": fixed_v},
        {"description": f"Upgrade {name} to {fixed_v}",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v}]},
        health,
        {"evidence_type": "FILE_STATE", "device_id": "device-001",
         "scope_key": "C:\\Program Files", "note": "the unchanged executable behind an updated ARP entry"},
    )


def group_partial_rollout(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    health = _health(rng)
    total = rng.choice([6, 8, 10])
    unreached = rng.choice([2, 3])
    devices: List[LatentDevice] = []
    targeted: List[str] = []
    for i in range(1, total + 1):
        did = f"device-{i:03d}"
        targeted.append(did)
        base = _base_state(rng, health)
        base.packages = [InstalledPackage(name, vuln_v, "machine", f"{{{name}-M}}")]
        reached = i <= total - unreached

        def mutate(s: DeviceState, reached=reached) -> None:
            if reached:
                s.packages = [InstalledPackage(name, fixed_v, "machine", f"{{{name}-M}}")]

        devices.append(_device(did, base, mutate, reboot_performed=False, enumerable=reached))
    return _world(
        case_id, "GROUP_PARTIAL_ROLLOUT", devices, targeted,
        _ok(total, reported=total - unreached), False,
        {"id": "PKG_BELOW_FIX", "op": "package_version_below", "package": name, "fixed_version": fixed_v},
        {"description": f"Upgrade {name} to {fixed_v} across the targeted group",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v}]},
        health,
        {"evidence_type": "GROUP_MEMBERSHIP", "device_id": targeted[-1],
         "scope_key": "group", "note": "the devices that never checked in"},
    )


def regression_introduced(rng: random.Random, case_id: str) -> LatentWorld:
    name, vuln_v, fixed_v = rng.choice(PRODUCTS)
    health = _health(rng)
    broken = health[0]
    base = _base_state(rng, health)
    base.packages = [InstalledPackage(name, vuln_v, "machine", f"{{{name}-M}}")]

    def mutate(s: DeviceState) -> None:
        s.packages = [InstalledPackage(name, fixed_v, "machine", f"{{{name}-M}}")]
        s.application_health[broken] = False

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "REGRESSION_INTRODUCED", [dev], ["device-001"], _ok(1), False,
        {"id": "PKG_BELOW_FIX", "op": "package_version_below", "package": name, "fixed_version": fixed_v},
        {"description": f"Upgrade {name} to {fixed_v}",
         "target_state_assertions": [
             {"id": "FIXED_PRESENT", "op": "package_present", "package": name, "version": fixed_v}]},
        health,
        {"evidence_type": "APPLICATION_HEALTH", "device_id": "device-001",
         "scope_key": "health", "note": f"the failing {broken} check"},
    )


def new_exposure_introduced(rng: random.Random, case_id: str) -> LatentWorld:
    path, insecure, secure = rng.choice(POLICY_KEYS)
    flag = rng.choice(RISK_FLAGS)
    health = _health(rng)
    base = _base_state(rng, health)
    base.registry = {path: insecure}

    def mutate(s: DeviceState) -> None:
        s.registry[path] = secure
        s.security_posture[flag] = True

    dev = _device("device-001", base, mutate, reboot_performed=False)
    return _world(
        case_id, "NEW_EXPOSURE_INTRODUCED", [dev], ["device-001"], _ok(1), False,
        {"id": "POLICY_INSECURE", "op": "registry_not_equals", "path": path, "value": secure},
        {"description": "Apply the policy value that disables the vulnerable behaviour",
         "target_state_assertions": [
             {"id": "POLICY_SET", "op": "registry_equals", "path": path, "value": secure}]},
        health,
        {"evidence_type": "SECURITY_POSTURE", "device_id": "device-001",
         "scope_key": "posture", "note": f"the newly set {flag} exposure"},
    )


def _registry_root(path: str) -> str:
    from .state import registry_root_of
    return registry_root_of(path)


BUILDERS: Dict[str, Callable[[random.Random, str], LatentWorld]] = {
    "GENUINE_REMEDIATION": genuine_remediation,
    "EXIT_ZERO_NO_CHANGE": exit_zero_no_change,
    "WRONG_REGISTRY_KEY": wrong_registry_key,
    "WRONG_PRODUCT_IDENTITY": wrong_product_identity,
    "SIDE_BY_SIDE_VULNERABLE": side_by_side_vulnerable,
    "PARTIAL_MULTI_PREDICATE": partial_multi_predicate,
    "SERVICE_RETURNS_AFTER_REBOOT": service_returns_after_reboot,
    "REBOOT_REQUIRED_NOT_PERFORMED": reboot_required_not_performed,
    "VULNERABLE_BINARY_ON_DISK": vulnerable_binary_on_disk,
    "INVENTORY_UPDATED_BINARY_UNCHANGED": inventory_updated_binary_unchanged,
    "GROUP_PARTIAL_ROLLOUT": group_partial_rollout,
    "REGRESSION_INTRODUCED": regression_introduced,
    "NEW_EXPOSURE_INTRODUCED": new_exposure_introduced,
}

assert set(BUILDERS) == set(FAMILIES)


def build_world(family: str, seed: int, case_id: str) -> LatentWorld:
    return BUILDERS[family](random.Random(seed), case_id)
