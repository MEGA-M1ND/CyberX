"""The real-collection path.

Every function here calls a gate first.  On a non-Windows host, or without both
environment gates and a hostname confirmation, construction and execution raise
before any command is assembled - there is no code path that reaches
`subprocess` without passing `require_real_lab` or `require_fixture_setup`.

The collectors themselves are PowerShell scripts in `powershell/`.  They are
read-only: they query, they never set.  The one script that writes anything is
the fixture provisioner, and it is behind the second gate.
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..lab.gates import require_fixture_setup, require_real_lab
from ..vocab import CollectorId

SCRIPTS: Dict[str, str] = {
    CollectorId.A_UNINSTALL_REGISTRY.value: "Collect-UninstallRegistry.ps1",
    CollectorId.B_EXPANDED_REGISTRY.value: "Collect-ExpandedRegistry.ps1",
    CollectorId.C_PACKAGE_PROVIDER.value: "Collect-PackageProvider.ps1",
    CollectorId.D_FILE_VERSION.value: "Collect-FileVersions.ps1",
    CollectorId.E_SERVICE_TASK.value: "Collect-ServicesAndTasks.ps1",
    CollectorId.F_COMPOSITE_ACTIVE.value: "Collect-Composite.ps1",
}

SETUP_SCRIPT = "New-LabFixtures.ps1"
CLEANUP_SCRIPT = "Remove-LabFixtures.ps1"
POWERSHELL_TIMEOUT_SECONDS = 900


@dataclass
class CollectorRun:
    collector_id: str
    payload: Dict[str, Any]
    seconds: float
    record_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {"collector_id": self.collector_id, "payload": self.payload,
                "seconds": self.seconds, "record_count": self.record_count}


def _powershell(script: Path, args: List[str], timeout: int = POWERSHELL_TIMEOUT_SECONDS
                ) -> Dict[str, Any]:  # pragma: no cover - Windows lab only
    command = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(script), *args]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"{script.name} failed ({proc.returncode}): {proc.stderr[:500]}")
    return json.loads(proc.stdout or "{}")


def run_collector(collector_id: str, script_dir: Path, target: Dict[str, Any],
                  extra_roots: Optional[List[str]] = None) -> CollectorRun:
    """Run one read-only collector on the confirmed lab VM."""
    require_real_lab()
    if collector_id not in SCRIPTS:
        raise KeyError(f"no script for collector {collector_id!r}")
    script = Path(script_dir) / SCRIPTS[collector_id]
    if not script.exists():
        raise FileNotFoundError(script)
    args = ["-FixtureId", str(target["fixture_id"]),
            "-FileRoot", str(target["file_root"]),
            "-RegistryRoot", str(target["registry_root"]),
            "-ArpPrefix", str(target["arp_prefix"])]
    if extra_roots:
        args += ["-ExtraRoots", ",".join(extra_roots)]
    started = time.perf_counter()
    payload = _powershell(script, args)  # pragma: no cover - Windows lab only
    seconds = time.perf_counter() - started  # pragma: no cover
    return CollectorRun(  # pragma: no cover
        collector_id=collector_id, payload=payload, seconds=round(seconds, 3),
        record_count=int(payload.get("record_count", 0)))


def provision_fixtures(script_dir: Path, plan_path: Path) -> Dict[str, Any]:
    """The only writing path in the experiment.  Two gates plus confirmation."""
    require_fixture_setup()
    script = Path(script_dir) / SETUP_SCRIPT
    if not script.exists():
        raise FileNotFoundError(script)
    return _powershell(script, ["-PlanPath", str(plan_path)])  # pragma: no cover


def remove_fixtures(script_dir: Path, plan_path: Path) -> Dict[str, Any]:
    require_fixture_setup()
    script = Path(script_dir) / CLEANUP_SCRIPT
    if not script.exists():
        raise FileNotFoundError(script)
    return _powershell(script, ["-PlanPath", str(plan_path)])  # pragma: no cover
