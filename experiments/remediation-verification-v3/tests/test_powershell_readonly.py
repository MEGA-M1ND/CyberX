"""The collector scripts must be read-only, and must not use Win32_Product."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

PS_DIR = Path(__file__).resolve().parents[1] / "powershell"
COLLECTORS = sorted(PS_DIR.glob("Collect-*.ps1"))
WRITERS = [PS_DIR / "New-LabFixtures.ps1", PS_DIR / "Remove-LabFixtures.ps1"]

# Cmdlets that change machine state. Add-Member and New-Object build in-memory
# objects and are not in this list; New-CollectorResult and Add-Fact are helpers
# defined in _Common.ps1.
MUTATING = [
    r"\bSet-ItemProperty\b", r"\bSet-Item\b", r"\bSet-Acl\b", r"\bSet-Service\b",
    r"\bNew-Item\b", r"\bNew-ItemProperty\b", r"\bNew-Service\b", r"\bNew-LocalUser\b",
    r"\bRemove-Item\b", r"\bRemove-Service\b", r"\bRemove-LocalUser\b",
    r"\bRegister-ScheduledTask\b", r"\bUnregister-ScheduledTask\b",
    r"\bStart-Service\b", r"\bStop-Service\b", r"\bStart-Process\b",
    r"\bCopy-Item\b", r"\bMove-Item\b", r"\bsc\.exe\b", r"\breg\s+load\b",
    r"\.SetValue\(", r"\.CreateSubKey\(", r"\.DeleteSubKey",
]


def _strip_comments(text: str) -> str:
    text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_collector_scripts_exist():
    assert len(COLLECTORS) == 6, [p.name for p in COLLECTORS]


@pytest.mark.parametrize("script", COLLECTORS, ids=lambda p: p.name)
def test_collectors_contain_no_mutating_cmdlet(script):
    code = _strip_comments(script.read_text())
    offenders = [pattern for pattern in MUTATING if re.search(pattern, code)]
    assert offenders == [], f"{script.name}: {offenders}"


@pytest.mark.parametrize("script", COLLECTORS, ids=lambda p: p.name)
def test_collectors_never_enumerate_win32_product(script):
    """Enumerating Win32_Product triggers an MSI consistency check per product."""
    code = _strip_comments(script.read_text())
    assert not re.search(r"(Get-CimInstance|Get-WmiObject|gwmi)[^\n]*Win32_Product", code)
    assert not re.search(r"\[wmi\]", code, flags=re.I)


@pytest.mark.parametrize("script", COLLECTORS, ids=lambda p: p.name)
def test_collectors_declare_their_scope_and_emit_a_timestamp(script):
    text = script.read_text()
    assert "claims_complete_for" in text
    assert "declared_exclusions" in text
    assert "New-CollectorResult" in text
    assert "reads_only" in text


@pytest.mark.parametrize("script", COLLECTORS, ids=lambda p: p.name)
def test_collectors_record_their_failures(script):
    """A collector that stays silent about what it could not read is the bug."""
    assert "Add-Failure" in script.read_text()


@pytest.mark.parametrize("script", WRITERS, ids=lambda p: p.name)
def test_writing_scripts_check_all_three_gates(script):
    text = script.read_text()
    assert "ALLOW_WINDOWS_FIXTURE_SETUP" in text
    assert "ALLOW_REAL_WINDOWS_LAB" in text
    assert "RV3_LAB_CONFIRMATION" in text
    assert "COMPUTERNAME" in text
    assert "throw" in text


def test_cleanup_removes_by_prefix_not_by_plan():
    """An interrupted provisioning run must still clean up completely."""
    text = Path(PS_DIR / "Remove-LabFixtures.ps1").read_text()
    for prefix in ("RV3Lab_*", "rv3lab_*", "C:\\RV3Lab"):
        assert prefix in text


def test_composite_never_mounts_an_unloaded_hive():
    text = _strip_comments((PS_DIR / "Collect-Composite.ps1").read_text())
    assert not re.search(r"reg\s+load", text, flags=re.I)
    assert not re.search(r"\bLoadHive\b", text)


def test_no_collector_opens_a_network_connection():
    for script in COLLECTORS:
        code = _strip_comments(script.read_text())
        for pattern in (r"Invoke-WebRequest", r"Invoke-RestMethod", r"New-Object\s+Net\.",
                        r"System\.Net\.WebClient", r"Test-NetConnection"):
            assert not re.search(pattern, code, flags=re.I), script.name
