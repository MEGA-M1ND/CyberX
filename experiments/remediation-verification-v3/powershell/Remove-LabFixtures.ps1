<#
.SYNOPSIS
  Remove every v3 lab fixture. WRITES TO THIS MACHINE. Disposable lab VM only.

.DESCRIPTION
  Cleanup is by prefix rather than by plan, so a partially-applied or
  interrupted provisioning run still cleans up completely. Everything the
  provisioner can create carries an RV3Lab_ / rv3lab_ prefix or lives under
  C:\RV3Lab.
#>
[CmdletBinding()]
param([string]$PlanPath = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if ($env:ALLOW_WINDOWS_FIXTURE_SETUP -ne '1' -or $env:ALLOW_REAL_WINDOWS_LAB -ne '1') {
    throw 'Both ALLOW_WINDOWS_FIXTURE_SETUP=1 and ALLOW_REAL_WINDOWS_LAB=1 are required.'
}
if ($env:RV3_LAB_CONFIRMATION -ne $env:COMPUTERNAME) {
    throw "RV3_LAB_CONFIRMATION must equal this machine's hostname ($env:COMPUTERNAME)."
}

$removed = New-Object System.Collections.ArrayList

foreach ($task in (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'RV3Lab_*' })) {
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    [void]$removed.Add("task:$($task.TaskName)")
}
foreach ($service in (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'RV3Lab_*' })) {
    & sc.exe delete $service.Name | Out-Null
    [void]$removed.Add("service:$($service.Name)")
}
foreach ($user in (Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'rv3lab_*' })) {
    Remove-LocalUser -Name $user.Name -ErrorAction SilentlyContinue
    [void]$removed.Add("user:$($user.Name)")
}

$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach ($base in $uninstallKeys) {
    foreach ($key in (Get-ChildItem $base -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'RV3Lab_*' })) {
        Remove-Item -LiteralPath $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        [void]$removed.Add("registry:$($key.PSPath)")
    }
}
foreach ($root in @('HKLM:\SOFTWARE\RV3Lab', 'HKLM:\SOFTWARE\WOW6432Node\RV3Lab', 'HKCU:\SOFTWARE\RV3Lab')) {
    if (Test-Path $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        [void]$removed.Add("registry:$root")
    }
}

if (Test-Path 'C:\RV3Lab') {
    # Drop the deny ACE first so the recursive delete is not blocked by the
    # permission-denied fixture.
    foreach ($dir in (Get-ChildItem 'C:\RV3Lab' -Recurse -Directory -ErrorAction SilentlyContinue)) {
        try {
            $acl = Get-Acl -LiteralPath $dir.FullName
            $denies = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
            foreach ($rule in $denies) { [void]$acl.RemoveAccessRule($rule) }
            if ($denies.Count -gt 0) { Set-Acl -LiteralPath $dir.FullName -AclObject $acl }
        } catch { }
    }
    Remove-Item -LiteralPath 'C:\RV3Lab' -Recurse -Force -ErrorAction SilentlyContinue
    [void]$removed.Add('files:C:\RV3Lab')
}

[pscustomobject]@{
    status = 'CLEANED'
    machine = $env:COMPUTERNAME
    cleaned_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    removed = $removed
    residue = @(
        @{ path = 'C:\RV3Lab'; present = (Test-Path 'C:\RV3Lab') },
        @{ path = 'HKLM:\SOFTWARE\RV3Lab'; present = (Test-Path 'HKLM:\SOFTWARE\RV3Lab') }
    )
} | ConvertTo-Json -Depth 6 -Compress
