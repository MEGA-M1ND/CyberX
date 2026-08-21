<#
.SYNOPSIS
  Create the v3 lab fixtures. WRITES TO THIS MACHINE. Disposable lab VM only.

.DESCRIPTION
  Consumes the provisioning plan emitted by the Python harness and creates only
  what the plan lists, all of it under prefixes that make cleanup exhaustive:

      C:\RV3Lab                          files
      HKLM/HKCU\SOFTWARE\RV3Lab          registry values
      ...\Uninstall\RV3Lab_*             synthetic Add/Remove Programs entries
      Service  RV3Lab_*                  disposable services
      Task     \RV3Lab_*                 disposable scheduled tasks
      User     rv3lab_*                  disposable local accounts

  Nothing vulnerable is installed. "Vulnerable" in this experiment means a
  version string below a threshold and a file in a particular place. The stub
  binary is a copy of an existing benign system executable.

.NOTES
  Requires ALLOW_WINDOWS_FIXTURE_SETUP=1 and ALLOW_REAL_WINDOWS_LAB=1 and
  RV3_LAB_CONFIRMATION set to this machine's own hostname. The script re-checks
  all three; the Python harness checks them too. Both must agree.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$PlanPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:ALLOW_WINDOWS_FIXTURE_SETUP -ne '1') {
    throw 'ALLOW_WINDOWS_FIXTURE_SETUP=1 is required. Refusing to write to this machine.'
}
if ($env:ALLOW_REAL_WINDOWS_LAB -ne '1') {
    throw 'ALLOW_REAL_WINDOWS_LAB=1 is required. Refusing to write to this machine.'
}
if ($env:RV3_LAB_CONFIRMATION -ne $env:COMPUTERNAME) {
    throw ("RV3_LAB_CONFIRMATION must equal this machine's hostname ($env:COMPUTERNAME). " +
           'Refusing: the confirmed target is not this host.')
}

$plan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json
$applied = New-Object System.Collections.ArrayList
$observed = New-Object System.Collections.ArrayList

function Set-RegistryValue {
    param([string]$Hive, [string]$View, [string]$Key, [string]$Name, $Value)
    $hiveEnum = switch ($Hive) {
        'HKLM' { [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKCU' { [Microsoft.Win32.RegistryHive]::CurrentUser }
        'HKU'  { [Microsoft.Win32.RegistryHive]::Users }
    }
    $viewEnum = [Microsoft.Win32.RegistryView]::$View
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hiveEnum, $viewEnum)
    try {
        $sub = $base.CreateSubKey($Key)
        try { if ($Name) { $sub.SetValue($Name, $Value) } } finally { $sub.Close() }
    } finally { $base.Close() }
}

foreach ($op in $plan.operations) {
    switch ($op.op) {
        'new_directory' {
            if ($op.args.PSObject.Properties.Name -contains 'remove') { continue }
            New-Item -ItemType Directory -Force -Path $op.args.path | Out-Null
            [void]$applied.Add($op.op + ':' + $op.args.path)
        }
        'place_stub_binary' {
            New-Item -ItemType Directory -Force -Path (Split-Path $op.args.dest -Parent) | Out-Null
            Copy-Item -LiteralPath $op.args.source -Destination $op.args.dest -Force
            # Record what the file actually reports, so ground truth rests on a
            # direct observation rather than on the plan's assumption.
            $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($op.args.dest)
            [void]$observed.Add([pscustomobject]@{
                kind = 'file'; path = $op.args.dest
                file_version = $info.FileVersion; product_version = $info.ProductVersion
                label = $op.args.label })
            [void]$applied.Add($op.op + ':' + $op.args.dest)
        }
        'write_registry_value' {
            if ($op.args.PSObject.Properties.Name -contains 'delete_key') { continue }
            Set-RegistryValue -Hive $op.args.hive -View $op.args.view -Key $op.args.key `
                              -Name 'Enabled' -Value $op.args.value
            [void]$applied.Add($op.op + ':' + $op.args.key)
        }
        'new_arp_entry' {
            $key = $op.args.key
            Set-RegistryValue -Hive $op.args.hive -View $op.args.view -Key $key `
                              -Name 'DisplayName' -Value $op.args.display_name
            Set-RegistryValue -Hive $op.args.hive -View $op.args.view -Key $key `
                              -Name 'DisplayVersion' -Value $op.args.display_version
            [void]$observed.Add([pscustomobject]@{
                kind = 'arp'; key = $key; hive = $op.args.hive; view = $op.args.view
                display_version = $op.args.display_version })
            [void]$applied.Add($op.op + ':' + $key)
        }
        'new_service' {
            if ($op.args.PSObject.Properties.Name -contains 'remove') { continue }
            New-Service -Name $op.args.name -BinaryPathName $op.args.binary `
                        -StartupType $op.args.startup -ErrorAction Stop | Out-Null
            [void]$observed.Add([pscustomobject]@{
                kind = 'service'; name = $op.args.name; startup = $op.args.startup
                state = $op.args.state })
            [void]$applied.Add($op.op + ':' + $op.args.name)
        }
        'new_scheduled_task' {
            if ($op.args.PSObject.Properties.Name -contains 'remove') { continue }
            $action = New-ScheduledTaskAction -Execute $op.args.action
            $trigger = if ($op.args.trigger -eq 'AtLogon') { New-ScheduledTaskTrigger -AtLogOn }
                       else { New-ScheduledTaskTrigger -AtStartup }
            Register-ScheduledTask -TaskName $op.args.name -Action $action -Trigger $trigger `
                                   -Force | Out-Null
            [void]$observed.Add([pscustomobject]@{ kind = 'task'; name = $op.args.name })
            [void]$applied.Add($op.op + ':' + $op.args.name)
        }
        'new_local_user' {
            if ($op.args.PSObject.Properties.Name -contains 'remove') { continue }
            if (-not (Get-LocalUser -Name $op.args.name -ErrorAction SilentlyContinue)) {
                $pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + '!Aa1') -AsPlainText -Force
                New-LocalUser -Name $op.args.name -Password $pw -AccountNeverExpires `
                              -Description 'RV3 disposable lab fixture account' | Out-Null
            }
            [void]$observed.Add([pscustomobject]@{ kind = 'user'; name = $op.args.name })
            [void]$applied.Add($op.op + ':' + $op.args.name)
        }
        'deny_read_acl' {
            if ($op.args.PSObject.Properties.Name -contains 'remove') { continue }
            $acl = Get-Acl -LiteralPath $op.args.path
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'Users', 'ReadData', 'ContainerInherit,ObjectInherit', 'None', 'Deny')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $op.args.path -AclObject $acl
            [void]$applied.Add($op.op + ':' + $op.args.path)
        }
        'unload_user_hive' { [void]$applied.Add($op.op + ':' + $op.args.user + ' (no action; hive is already unloaded)') }
        'touch_inventory_cache' { [void]$applied.Add($op.op + ':' + $op.args.key + ' (simulated cache age)') }
        default { throw "unsupported provisioning op: $($op.op)" }
    }
}

[pscustomobject]@{
    status = 'PROVISIONED'
    machine = $env:COMPUTERNAME
    provisioned_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    applied = $applied
    observed_ground_truth = $observed
} | ConvertTo-Json -Depth 8 -Compress
