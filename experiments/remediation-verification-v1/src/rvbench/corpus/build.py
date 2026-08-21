"""Deterministic construction of the 48-case benchmark corpus.

The corpus is authored here in code and *emitted* to three separate JSON files
so that the leakage boundary is a filesystem boundary, not a convention:

    cases/public/cases.json           -> verifier-visible
    cases/simulation/scenarios.json   -> harness-only
    cases/ground_truth/labels.json    -> scorer-only (derived, not hand-written)

Re-running this module must produce byte-identical files; the manifest SHA-256
depends on it.  Nothing here uses randomness or the clock.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

SEED = 20260821  # fixed, recorded in run metadata; no stochastic step actually uses it

REG_SMB = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1"
REG_TLS = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Enabled"
REG_MACRO = "HKLM\\SOFTWARE\\Policies\\Acme\\Office\\BlockMacrosFromInternet"
REG_LEGACY_AUTH = "HKLM\\SOFTWARE\\AcmeEnterprise\\LegacyAuthEnabled"
REG_DECOY = "HKLM\\SOFTWARE\\WOW6432Node\\Policies\\Acme\\Office\\BlockMacrosFromInternet"

DEFAULT_HEALTH = ["lob_app_starts", "endpoint_agent_healthy"]


def _state(
    device_id: str = "device-001",
    packages: Optional[Dict[str, List[str]]] = None,
    registry: Optional[Dict[str, Any]] = None,
    services: Optional[Dict[str, Dict[str, str]]] = None,
    files: Optional[Dict[str, Dict[str, Any]]] = None,
    patches: Optional[Dict[str, Dict[str, bool]]] = None,
    reboot_pending: bool = False,
    health: Optional[Dict[str, bool]] = None,
    flags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base_health = {c: True for c in DEFAULT_HEALTH}
    if health:
        base_health.update(health)
    return {
        "device_id": device_id,
        "os": "windows",
        "packages": packages or {},
        "registry": registry or {},
        "services": services or {},
        "files": files or {},
        "patches": patches or {},
        "reboot_pending": reboot_pending,
        "health_checks": base_health,
        "security_flags": flags or {},
    }


def _exec(exit_code: int = 0, status: str = "Succeeded", deploy: str = "Succeeded",
          targeted: int = 1, reported: int = 1, stdout: str = "") -> Dict[str, Any]:
    return {
        "exit_code": exit_code,
        "execution_status": status,
        "deployment_status": deploy,
        "stdout": stdout,
        "stderr": "",
        "devices_targeted": targeted,
        "devices_reported_success": reported,
        "duration_ms": 1000,
    }


_CASES: List[Dict[str, Any]] = []


def case(
    case_id: str,
    category: str,
    title: str,
    vuln: Dict[str, Any],
    intent: str,
    assertions: List[Dict[str, Any]],
    initial: Any,
    ops: Any,
    execution: Dict[str, Any],
    health_checks: Optional[List[str]] = None,
    fleet_size: int = 1,
    environment: Optional[Dict[str, Any]] = None,
    reboot_effects: Optional[List[Dict[str, Any]]] = None,
    notes: str = "",
) -> None:
    initial_states = initial if isinstance(initial, list) else [initial]
    remediation_ops = ops if (ops and isinstance(ops[0], list)) else [ops]
    if len(remediation_ops) == 1 and len(initial_states) > 1:
        remediation_ops = remediation_ops * len(initial_states)
    _CASES.append(
        {
            "public": {
                "case_id": case_id,
                "title": title,
                "os": "windows",
                "fleet_size": fleet_size,
                "vulnerability_predicate": vuln,
                "remediation_intent": {
                    "description": intent,
                    "target_state_assertions": assertions,
                },
                "required_health_checks": health_checks or list(DEFAULT_HEALTH),
                "notes": notes,
            },
            "scenario": {
                "case_id": case_id,
                "initial_states": initial_states,
                "remediation_ops": remediation_ops,
                "execution_result": execution,
                "reboot_effects": reboot_effects or [],
                "environment": environment or {},
            },
            "category": category,
        }
    )


# --------------------------------------------------------------------------- #
# Reusable predicate fragments
# --------------------------------------------------------------------------- #
VULN_READER = {"id": "READER_BELOW_145", "op": "package_version_below", "package": "AcmeReader", "fixed_version": "1.4.5"}
VULN_SMB = {"id": "SMB1_REG_INSECURE", "op": "registry_not_equals", "path": REG_SMB, "value": 0}
VULN_MACRO = {"id": "MACRO_POLICY_INSECURE", "op": "registry_not_equals", "path": REG_MACRO, "value": 1}
VULN_LEGACY_DLL = {"id": "LEGACY_DLL_PRESENT", "op": "file_exists", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"}
VULN_KB = {"id": "KB5031234_MISSING", "op": "patch_missing", "kb": "KB5031234"}


def build() -> List[Dict[str, Any]]:
    _CASES.clear()
    _category_a()
    _category_b()
    _category_c()
    _category_d()
    _category_e()
    _category_f()
    _category_g()
    _category_h()
    _category_i()
    _category_j()
    _category_k()
    _category_l()
    return list(_CASES)


# --------------------------------------------------------------------------- #
# Category A - genuine successful remediation (8)
# --------------------------------------------------------------------------- #
def _category_a() -> None:
    case("A-01", "A_GENUINE_SUCCESS", "AcmeReader upgraded 1.4.2 -> 1.4.5, old build removed",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 and remove the vulnerable build",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"},
          {"id": "READER_142_ABSENT", "op": "package_absent", "package": "AcmeReader", "version": "1.4.2"}],
         _state(packages={"AcmeReader": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}],
         _exec())

    case("A-02", "A_GENUINE_SUCCESS", "SMB1 disabled via registry mitigation",
         VULN_SMB, "Set the SMB1 server parameter to 0",
         [{"id": "SMB1_REG_SECURE", "op": "registry_equals", "path": REG_SMB, "value": 0}],
         _state(registry={REG_SMB: 1}),
         [{"op": "set_registry", "path": REG_SMB, "value": 0}],
         _exec())

    case("A-03", "A_GENUINE_SUCCESS", "Vulnerable legacy DLL removed",
         VULN_LEGACY_DLL, "Delete the vulnerable legacy DLL",
         [{"id": "LEGACY_DLL_GONE", "op": "file_absent", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"}],
         _state(files={"C:\\Program Files\\Acme\\legacy\\acmelegacy.dll": {"exists": True, "version": "1.0.0"}}),
         [{"op": "delete_file", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"}],
         _exec())

    case("A-04", "A_GENUINE_SUCCESS", "Security update KB5031234 installed, no reboot required",
         VULN_KB, "Install KB5031234",
         [{"id": "KB_INSTALLED", "op": "patch_installed", "kb": "KB5031234"}],
         _state(patches={"KB5031234": {"installed": False, "staged": False}}),
         [{"op": "install_patch", "kb": "KB5031234", "requires_reboot": False}],
         _exec())

    case("A-05", "A_GENUINE_SUCCESS", "Vulnerable listener service stopped and disabled",
         {"id": "ACMESVC_RUNNING", "op": "service_running", "service": "AcmeSvc"},
         "Stop AcmeSvc and set startup type to disabled",
         [{"id": "ACMESVC_STOPPED", "op": "service_stopped", "service": "AcmeSvc"},
          {"id": "ACMESVC_DISABLED", "op": "service_startup_is", "service": "AcmeSvc", "startup_type": "disabled"}],
         _state(services={"AcmeSvc": {"status": "running", "startup_type": "automatic"}}),
         [{"op": "set_service", "service": "AcmeSvc", "status": "stopped", "startup_type": "disabled"}],
         _exec())

    case("A-06", "A_GENUINE_SUCCESS", "Composite mitigation: both required components remediated",
         {"op": "any_of", "operands": [VULN_READER, VULN_MACRO]},
         "Upgrade AcmeReader and apply the macro-blocking policy",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"},
          {"id": "MACRO_POLICY_SECURE", "op": "registry_equals", "path": REG_MACRO, "value": 1}],
         _state(packages={"AcmeReader": ["1.4.2"]}, registry={REG_MACRO: 0}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True},
          {"op": "set_registry", "path": REG_MACRO, "value": 1}],
         _exec())

    case("A-07", "A_GENUINE_SUCCESS", "Fleet of 10 fully remediated",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 across the targeted group",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         [_state(f"device-{i:03d}", packages={"AcmeReader": ["1.4.2"]}) for i in range(1, 11)],
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}],
         _exec(targeted=10, reported=10), fleet_size=10)

    case("A-08", "A_GENUINE_SUCCESS", "Noisy non-zero exit code, but the endpoint is genuinely fixed",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 (post-install cleanup step returns 1)",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"},
          {"id": "READER_142_ABSENT", "op": "package_absent", "package": "AcmeReader", "version": "1.4.2"}],
         _state(packages={"AcmeReader": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}],
         _exec(exit_code=1, status="Failed", deploy="Error", stdout="cleanup: could not delete temp folder"),
         notes="Included so that a verifier cannot score well by simply mirroring exit codes.")


# --------------------------------------------------------------------------- #
# Category B - exit 0 but nothing changed (4)
# --------------------------------------------------------------------------- #
def _category_b() -> None:
    case("B-01", "B_EXIT0_NO_CHANGE", "Installer returns 0, package still on the vulnerable build",
         VULN_READER, "Upgrade AcmeReader to 1.4.5",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"]}), [{"op": "noop"}],
         _exec(stdout="Installation completed successfully."))

    case("B-02", "B_EXIT0_NO_CHANGE", "Registry write silently suppressed by policy, exit 0",
         VULN_SMB, "Set the SMB1 server parameter to 0",
         [{"id": "SMB1_REG_SECURE", "op": "registry_equals", "path": REG_SMB, "value": 0}],
         _state(registry={REG_SMB: 1}), [{"op": "noop"}], _exec())

    case("B-03", "B_EXIT0_NO_CHANGE", "File delete swallowed by error handling, exit 0",
         VULN_LEGACY_DLL, "Delete the vulnerable legacy DLL",
         [{"id": "LEGACY_DLL_GONE", "op": "file_absent", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"}],
         _state(files={"C:\\Program Files\\Acme\\legacy\\acmelegacy.dll": {"exists": True, "version": "1.0.0"}}),
         [{"op": "noop"}], _exec(stdout="Remediation complete."))

    case("B-04", "B_EXIT0_NO_CHANGE", "Update wrapper reports success, patch never installed",
         VULN_KB, "Install KB5031234",
         [{"id": "KB_INSTALLED", "op": "patch_installed", "kb": "KB5031234"}],
         _state(patches={"KB5031234": {"installed": False, "staged": False}}), [{"op": "noop"}], _exec())


# --------------------------------------------------------------------------- #
# Category C - wrong target changed (4)
# --------------------------------------------------------------------------- #
def _category_c() -> None:
    case("C-01", "C_WRONG_TARGET", "Macro policy written under WOW6432Node, vulnerable key is the 64-bit hive",
         VULN_MACRO, "Apply the macro-blocking policy value",
         [{"id": "DECOY_POLICY_SET", "op": "registry_equals", "path": REG_DECOY, "value": 1}],
         _state(registry={REG_MACRO: 0, REG_DECOY: 0}),
         [{"op": "set_registry", "path": REG_DECOY, "value": 1}], _exec())

    case("C-02", "C_WRONG_TARGET", "MSI package upgraded, vulnerable per-user package untouched",
         {"id": "READER_USER_BELOW_145", "op": "package_version_below", "package": "AcmeReader (per-user)", "fixed_version": "1.4.5"},
         "Upgrade the AcmeReader MSI package to 1.4.5",
         [{"id": "MSI_145_PRESENT", "op": "package_present", "package": "AcmeReader (MSI)", "version": "1.4.5"}],
         _state(packages={"AcmeReader (MSI)": ["1.4.2"], "AcmeReader (per-user)": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader (MSI)", "version": "1.4.5", "remove_old": True}],
         _exec())

    case("C-03", "C_WRONG_TARGET", "Deprecated service disabled, the actually-listening service still runs",
         {"id": "ACMESVC_RUNNING", "op": "service_running", "service": "AcmeSvc"},
         "Stop and disable the Acme listener service",
         [{"id": "ACMESVCOLD_DISABLED", "op": "service_startup_is", "service": "AcmeSvcOld", "startup_type": "disabled"}],
         _state(services={"AcmeSvc": {"status": "running", "startup_type": "automatic"},
                          "AcmeSvcOld": {"status": "stopped", "startup_type": "manual"}}),
         [{"op": "set_service", "service": "AcmeSvcOld", "status": "stopped", "startup_type": "disabled"}],
         _exec())

    case("C-04", "C_WRONG_TARGET", "DLL deleted from the x86 path, vulnerable copy lives in the 64-bit path",
         VULN_LEGACY_DLL, "Delete the vulnerable legacy DLL",
         [{"id": "X86_DLL_GONE", "op": "file_absent", "path": "C:\\Program Files (x86)\\Acme\\legacy\\acmelegacy.dll"}],
         _state(files={"C:\\Program Files\\Acme\\legacy\\acmelegacy.dll": {"exists": True, "version": "1.0.0"},
                       "C:\\Program Files (x86)\\Acme\\legacy\\acmelegacy.dll": {"exists": True, "version": "1.0.0"}}),
         [{"op": "delete_file", "path": "C:\\Program Files (x86)\\Acme\\legacy\\acmelegacy.dll"}], _exec())


# --------------------------------------------------------------------------- #
# Category D - temporary remediation (4)
# --------------------------------------------------------------------------- #
def _category_d() -> None:
    case("D-01", "D_TEMPORARY", "Service stopped but startup type left automatic",
         {"id": "ACMESVC_RUNNING", "op": "service_running", "service": "AcmeSvc"},
         "Stop the AcmeSvc listener",
         [{"id": "ACMESVC_STOPPED", "op": "service_stopped", "service": "AcmeSvc"}],
         _state(services={"AcmeSvc": {"status": "running", "startup_type": "automatic"}}),
         [{"op": "set_service", "service": "AcmeSvc", "status": "stopped"}], _exec())

    case("D-02", "D_TEMPORARY", "Registry mitigation reverted by the group policy refresh after reboot",
         VULN_SMB, "Set the SMB1 server parameter to 0",
         [{"id": "SMB1_REG_SECURE", "op": "registry_equals", "path": REG_SMB, "value": 0}],
         _state(registry={REG_SMB: 1}),
         [{"op": "set_registry", "path": REG_SMB, "value": 0}], _exec(),
         reboot_effects=[{"op": "set_registry", "path": REG_SMB, "value": 1}])

    case("D-03", "D_TEMPORARY", "RDP NLA re-enabled at runtime, reverts on restart",
         {"id": "RDP_NLA_DISABLED", "op": "flag_true", "flag": "rdp_nla_disabled"},
         "Re-enable Network Level Authentication for RDP",
         [{"id": "NLA_FLAG_CLEARED", "op": "flag_equals", "flag": "rdp_nla_disabled", "value": False}],
         _state(flags={"rdp_nla_disabled": True}),
         [{"op": "set_flag", "flag": "rdp_nla_disabled", "value": False}], _exec(),
         reboot_effects=[{"op": "set_flag", "flag": "rdp_nla_disabled", "value": True}])

    case("D-04", "D_TEMPORARY", "Vulnerable binary deleted, recreated by a scheduled task on boot",
         VULN_LEGACY_DLL, "Delete the vulnerable legacy DLL",
         [{"id": "LEGACY_DLL_GONE", "op": "file_absent", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"}],
         _state(files={"C:\\Program Files\\Acme\\legacy\\acmelegacy.dll": {"exists": True, "version": "1.0.0"}}),
         [{"op": "delete_file", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"}], _exec(),
         reboot_effects=[{"op": "create_file", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll", "version": "1.0.0"}])


# --------------------------------------------------------------------------- #
# Category E - side-by-side vulnerable version remains (4)
# --------------------------------------------------------------------------- #
def _category_e() -> None:
    case("E-01", "E_SIDE_BY_SIDE", "1.4.5 installed alongside the vulnerable 1.4.2",
         VULN_READER, "Install AcmeReader 1.4.5",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": False}], _exec())

    case("E-02", "E_SIDE_BY_SIDE", "New binary deployed, vulnerable binary left at the legacy path",
         {"id": "LEGACY_BIN_BELOW_145", "op": "file_version_below", "path": "C:\\Program Files\\Acme\\legacy\\acme.exe", "fixed_version": "1.4.5"},
         "Deploy acme.exe 1.4.5 to the current install path",
         [{"id": "CURRENT_BIN_145", "op": "file_exists", "path": "C:\\Program Files\\Acme\\current\\acme.exe"}],
         _state(files={"C:\\Program Files\\Acme\\legacy\\acme.exe": {"exists": True, "version": "1.4.2"}}),
         [{"op": "create_file", "path": "C:\\Program Files\\Acme\\current\\acme.exe", "version": "1.4.5"}], _exec())

    case("E-03", "E_SIDE_BY_SIDE", "Duplicate install detected: two AcmeReader builds registered",
         {"id": "READER_DUPLICATE_VULN", "op": "package_duplicate_below", "package": "AcmeReader", "fixed_version": "1.4.5"},
         "Install AcmeReader 1.4.5",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": False}], _exec())

    case("E-04", "E_SIDE_BY_SIDE", "Side-by-side vulnerable build hidden from the inventory collector",
         VULN_READER, "Install AcmeReader 1.4.5",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": False}], _exec(),
         environment={"blind_spot_package_versions": {"AcmeReader": ["1.4.2"]},
                      "collector_note": "inventory enumerates machine-scope ARP entries only"},
         notes="Silent-blindness variant: the collector reports a complete inventory that is not complete.")


# --------------------------------------------------------------------------- #
# Category F - partial remediation of a composite vulnerability (4)
# --------------------------------------------------------------------------- #
def _category_f() -> None:
    case("F-01", "F_PARTIAL", "Package upgraded, required registry mitigation never applied",
         {"op": "any_of", "operands": [VULN_READER, VULN_MACRO]},
         "Upgrade AcmeReader to 1.4.5 (component 1 of 2)",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"]}, registry={REG_MACRO: 0}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}], _exec())

    case("F-02", "F_PARTIAL", "One of two required security updates installed",
         {"op": "any_of", "operands": [VULN_KB, {"id": "KB5031999_MISSING", "op": "patch_missing", "kb": "KB5031999"}]},
         "Install the two required security updates",
         [{"id": "KB5031234_INSTALLED", "op": "patch_installed", "kb": "KB5031234"}],
         _state(patches={"KB5031234": {"installed": False, "staged": False},
                         "KB5031999": {"installed": False, "staged": False}}),
         [{"op": "install_patch", "kb": "KB5031234", "requires_reboot": False}], _exec())

    case("F-03", "F_PARTIAL", "First vulnerable DLL removed, second removal errored",
         {"op": "any_of", "operands": [
             {"id": "DLL_A_PRESENT", "op": "file_exists", "path": "C:\\Acme\\a\\vuln.dll"},
             {"id": "DLL_B_PRESENT", "op": "file_exists", "path": "C:\\Acme\\b\\vuln.dll"}]},
         "Remove both vulnerable DLL copies",
         [{"id": "DLL_A_GONE", "op": "file_absent", "path": "C:\\Acme\\a\\vuln.dll"}],
         _state(files={"C:\\Acme\\a\\vuln.dll": {"exists": True, "version": "1.0.0"},
                       "C:\\Acme\\b\\vuln.dll": {"exists": True, "version": "1.0.0"}}),
         [{"op": "delete_file", "path": "C:\\Acme\\a\\vuln.dll"}],
         _exec(exit_code=1, status="Failed", deploy="Error", stdout="access denied on C:\\Acme\\b\\vuln.dll"))

    case("F-04", "F_PARTIAL", "One of two vulnerable listeners stopped",
         {"op": "any_of", "operands": [
             {"id": "SVC1_RUNNING", "op": "service_running", "service": "AcmeSvc"},
             {"id": "SVC2_RUNNING", "op": "service_running", "service": "AcmeRelay"}]},
         "Stop and disable both vulnerable listeners",
         [{"id": "SVC1_DISABLED", "op": "service_startup_is", "service": "AcmeSvc", "startup_type": "disabled"}],
         _state(services={"AcmeSvc": {"status": "running", "startup_type": "automatic"},
                          "AcmeRelay": {"status": "running", "startup_type": "automatic"}}),
         [{"op": "set_service", "service": "AcmeSvc", "status": "stopped", "startup_type": "disabled"}],
         _exec(exit_code=1, status="CompletedWithErrors", deploy="Error"))


# --------------------------------------------------------------------------- #
# Category G - partial fleet rollout (4)
# --------------------------------------------------------------------------- #
def _category_g() -> None:
    fixed = [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}]
    assertion = [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}]

    case("G-01", "G_FLEET_PARTIAL", "10 targeted, 3 offline and never enumerated, console reports success",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 across the targeted group", assertion,
         [_state(f"device-{i:03d}", packages={"AcmeReader": ["1.4.2"]}) for i in range(1, 8)],
         fixed, _exec(targeted=10, reported=7), fleet_size=10)

    case("G-02", "G_FLEET_PARTIAL", "12 targeted, 9 enumerated, remaining devices unreachable",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 across the targeted group", assertion,
         [_state(f"device-{i:03d}", packages={"AcmeReader": ["1.4.2"]}) for i in range(1, 10)],
         fixed, _exec(targeted=12, reported=9), fleet_size=12)

    case("G-03", "G_FLEET_PARTIAL", "All 10 enumerated, remediation no-opped on 3 of them",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 across the targeted group", assertion,
         [_state(f"device-{i:03d}", packages={"AcmeReader": ["1.4.2"]}) for i in range(1, 11)],
         [fixed if i < 7 else [{"op": "noop"}] for i in range(10)],
         _exec(targeted=10, reported=10), fleet_size=10)

    case("G-04", "G_FLEET_PARTIAL", "All 10 got the new build; 2 kept the old build side-by-side",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 across the targeted group", assertion,
         [_state(f"device-{i:03d}", packages={"AcmeReader": ["1.4.2"]}) for i in range(1, 11)],
         [fixed if i < 8 else [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": False}]
          for i in range(10)],
         _exec(targeted=10, reported=10), fleet_size=10)


# --------------------------------------------------------------------------- #
# Category H - functional regression (4)
# --------------------------------------------------------------------------- #
def _category_h() -> None:
    case("H-01", "H_REGRESSION", "Upgrade fixed the CVE and broke the line-of-business app",
         VULN_READER, "Upgrade AcmeReader to 1.4.5",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True},
          {"op": "set_health", "check": "lob_app_starts", "value": False}], _exec())

    case("H-02", "H_REGRESSION", "Disabling the spooler-adjacent service broke printing",
         {"id": "ACMESVC_RUNNING", "op": "service_running", "service": "AcmeSvc"},
         "Stop and disable AcmeSvc",
         [{"id": "ACMESVC_DISABLED", "op": "service_startup_is", "service": "AcmeSvc", "startup_type": "disabled"}],
         _state(services={"AcmeSvc": {"status": "running", "startup_type": "automatic"}},
                health={"print_service_healthy": True}),
         [{"op": "set_service", "service": "AcmeSvc", "status": "stopped", "startup_type": "disabled"},
          {"op": "set_health", "check": "print_service_healthy", "value": False}], _exec(),
         health_checks=DEFAULT_HEALTH + ["print_service_healthy"])

    case("H-03", "H_REGRESSION", "TLS 1.0 disabled; the VPN client can no longer connect",
         {"id": "TLS10_ENABLED_REG", "op": "registry_equals", "path": REG_TLS, "value": 1},
         "Disable TLS 1.0 in SCHANNEL",
         [{"id": "TLS10_REG_DISABLED", "op": "registry_equals", "path": REG_TLS, "value": 0}],
         _state(registry={REG_TLS: 1}, health={"vpn_client_connects": True}),
         [{"op": "set_registry", "path": REG_TLS, "value": 0},
          {"op": "set_health", "check": "vpn_client_connects", "value": False}], _exec(),
         health_checks=DEFAULT_HEALTH + ["vpn_client_connects"])

    case("H-04", "H_REGRESSION", "Patch installed; the endpoint security agent stopped reporting",
         VULN_KB, "Install KB5031234",
         [{"id": "KB_INSTALLED", "op": "patch_installed", "kb": "KB5031234"}],
         _state(patches={"KB5031234": {"installed": False, "staged": False}}),
         [{"op": "install_patch", "kb": "KB5031234", "requires_reboot": False},
          {"op": "set_health", "check": "endpoint_agent_healthy", "value": False}], _exec())


# --------------------------------------------------------------------------- #
# Category I - new security risk introduced (3)
# --------------------------------------------------------------------------- #
def _category_i() -> None:
    case("I-01", "I_NEW_RISK", "SMB1 disabled by turning the host firewall off",
         VULN_SMB, "Disable SMB1",
         [{"id": "SMB1_REG_SECURE", "op": "registry_equals", "path": REG_SMB, "value": 0}],
         _state(registry={REG_SMB: 1}, flags={"host_firewall_disabled": False}),
         [{"op": "set_registry", "path": REG_SMB, "value": 0},
          {"op": "set_flag", "flag": "host_firewall_disabled", "value": True}], _exec())

    case("I-02", "I_NEW_RISK", "Patch applied after relaxing script execution policy, never restored",
         VULN_KB, "Install KB5031234",
         [{"id": "KB_INSTALLED", "op": "patch_installed", "kb": "KB5031234"}],
         _state(patches={"KB5031234": {"installed": False, "staged": False}},
                flags={"unrestricted_script_policy": False}),
         [{"op": "install_patch", "kb": "KB5031234", "requires_reboot": False},
          {"op": "set_flag", "flag": "unrestricted_script_policy", "value": True}], _exec())

    case("I-03", "I_NEW_RISK", "Remediation added a local admin account the collector does not report",
         VULN_LEGACY_DLL, "Delete the vulnerable legacy DLL",
         [{"id": "LEGACY_DLL_GONE", "op": "file_absent", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"}],
         _state(files={"C:\\Program Files\\Acme\\legacy\\acmelegacy.dll": {"exists": True, "version": "1.0.0"}},
                flags={"unexpected_local_admin": False}),
         [{"op": "delete_file", "path": "C:\\Program Files\\Acme\\legacy\\acmelegacy.dll"},
          {"op": "set_flag", "flag": "unexpected_local_admin", "value": True}], _exec(),
         environment={"blind_spot_flags": ["unexpected_local_admin"],
                      "collector_note": "local group membership is not part of the collected posture snapshot"},
         notes="Silent-blindness variant: the new risk exists but is outside the collector's schema.")


# --------------------------------------------------------------------------- #
# Category J - reboot required (3)
# --------------------------------------------------------------------------- #
def _category_j() -> None:
    case("J-01", "J_REBOOT_REQUIRED", "Update staged successfully; endpoint vulnerable until reboot",
         VULN_KB, "Install KB5031234",
         [{"id": "KB_APPLIED", "op": "any_of", "operands": [
             {"op": "patch_installed", "kb": "KB5031234"},
             {"op": "patch_staged", "kb": "KB5031234"}]}],
         _state(patches={"KB5031234": {"installed": False, "staged": False}}),
         [{"op": "install_patch", "kb": "KB5031234", "requires_reboot": True}], _exec())

    case("J-02", "J_REBOOT_REQUIRED", "Cipher-suite hardening written to the registry, active only after restart",
         {"id": "LEGACY_CIPHER_ACTIVE", "op": "flag_true", "flag": "legacy_cipher_active"},
         "Harden the SCHANNEL cipher suite configuration",
         [{"id": "TLS10_REG_DISABLED", "op": "registry_equals", "path": REG_TLS, "value": 0}],
         _state(registry={REG_TLS: 1}, flags={"legacy_cipher_active": True}),
         [{"op": "set_registry", "path": REG_TLS, "value": 0}, {"op": "set_reboot_pending", "value": True}],
         _exec(), reboot_effects=[{"op": "set_flag", "flag": "legacy_cipher_active", "value": False}])

    case("J-03", "J_REBOOT_REQUIRED", "Servicing stack update staged, console shows Compliant",
         {"id": "KB5040001_MISSING", "op": "patch_missing", "kb": "KB5040001"},
         "Install KB5040001",
         [{"id": "KB_APPLIED", "op": "any_of", "operands": [
             {"op": "patch_installed", "kb": "KB5040001"},
             {"op": "patch_staged", "kb": "KB5040001"}]}],
         _state(patches={"KB5040001": {"installed": False, "staged": False}}),
         [{"op": "install_patch", "kb": "KB5040001", "requires_reboot": True}],
         _exec(status="Compliant", deploy="Compliant"))


# --------------------------------------------------------------------------- #
# Category K - incorrect vulnerability match (3)
# --------------------------------------------------------------------------- #
def _category_k() -> None:
    case("K-01", "K_WRONG_VULN_MATCH", "Consumer edition patched; the vulnerable Enterprise edition is a different product",
         {"id": "READER_ENT_BELOW_145", "op": "package_version_below", "package": "AcmeReader Enterprise", "fixed_version": "1.4.5"},
         "Upgrade AcmeReader to 1.4.5",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"], "AcmeReader Enterprise": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}], _exec())

    case("K-02", "K_WRONG_VULN_MATCH", "Superseded KB installed; the advisory requires a different KB",
         {"id": "KB5040001_MISSING", "op": "patch_missing", "kb": "KB5040001"},
         "Install KB5031234 as remediation for the advisory",
         [{"id": "KB5031234_INSTALLED", "op": "patch_installed", "kb": "KB5031234"}],
         _state(patches={"KB5031234": {"installed": False, "staged": False},
                         "KB5040001": {"installed": False, "staged": False}}),
         [{"op": "install_patch", "kb": "KB5031234", "requires_reboot": False}], _exec())

    case("K-03", "K_WRONG_VULN_MATCH", "Legacy-auth key set in the wrong hive; the real key is outside collection scope",
         {"id": "LEGACY_AUTH_ENABLED", "op": "registry_equals", "path": REG_LEGACY_AUTH, "value": 1},
         "Disable legacy authentication",
         [{"id": "DECOY_LEGACY_AUTH_CLEARED", "op": "registry_equals", "path": REG_DECOY, "value": 0}],
         _state(registry={REG_LEGACY_AUTH: 1, REG_DECOY: 1}),
         [{"op": "set_registry", "path": REG_DECOY, "value": 0}], _exec(),
         environment={"blind_spot_registry_paths": [REG_LEGACY_AUTH],
                      "collector_note": "vendor hive is not in the configured registry collection scope"},
         notes="Silent-blindness variant: the vulnerable key is invisible to the collector, so it reads as clean.")


# --------------------------------------------------------------------------- #
# Category L - evidence missing (3)
# --------------------------------------------------------------------------- #
def _category_l() -> None:
    case("L-01", "L_EVIDENCE_MISSING", "Software inventory could not be collected",
         VULN_READER, "Upgrade AcmeReader to 1.4.5",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         _state(packages={"AcmeReader": ["1.4.2"]}),
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}], _exec(),
         environment={"unavailable_evidence": ["PACKAGE_STATE"],
                      "collector_note": "WMI query timed out; software inventory unavailable"})

    case("L-02", "L_EVIDENCE_MISSING", "Registry fix verified, but no smoke-test evidence could be gathered",
         VULN_SMB, "Set the SMB1 server parameter to 0",
         [{"id": "SMB1_REG_SECURE", "op": "registry_equals", "path": REG_SMB, "value": 0}],
         _state(registry={REG_SMB: 1}),
         [{"op": "set_registry", "path": REG_SMB, "value": 0}], _exec(),
         environment={"unavailable_evidence": ["SMOKE_TEST"],
                      "collector_note": "health probe agent not installed on this endpoint"},
         notes="The target condition really was fixed; the point is that regression cannot be ruled out.")

    case("L-03", "L_EVIDENCE_MISSING", "Fleet membership could not be enumerated for a group deployment",
         VULN_READER, "Upgrade AcmeReader to 1.4.5 across the targeted group",
         [{"id": "READER_145_PRESENT", "op": "package_present", "package": "AcmeReader", "version": "1.4.5"}],
         [_state(f"device-{i:03d}", packages={"AcmeReader": ["1.4.2"]}) for i in range(1, 9)],
         [{"op": "install_package", "package": "AcmeReader", "version": "1.4.5", "remove_old": True}],
         _exec(targeted=8, reported=8), fleet_size=8,
         environment={"unavailable_evidence": ["FLEET_COVERAGE"],
                      "collector_note": "group membership API returned 503"})
