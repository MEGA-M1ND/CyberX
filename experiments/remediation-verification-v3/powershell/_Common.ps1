# Shared helpers for the v3 read-only collectors.
#
# Every collector emits the same envelope: its scope contract, the decisive
# facts it resolved, the collections that failed, and a timestamp. The contract
# is emitted by the collector itself so it can be diffed against the contract
# this repository declares in src/rv3/contracts/catalog.py.
#
# Nothing here writes. There is no Set-, New-, Remove- or Stop- cmdlet in any
# collector script, and no use of Win32_Product: enumerating that class triggers
# an MSI consistency check against every registered product, which is a
# write-adjacent side effect.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-CollectorResult {
    param(
        [Parameter(Mandatory)][string]$CollectorId,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][hashtable]$Scope
    )
    [pscustomobject]@{
        collector_id            = $CollectorId
        collector_version       = $Version
        collected_at_utc        = (Get-Date).ToUniversalTime().ToString('o')
        machine                 = $env:COMPUTERNAME
        scope                   = $Scope
        resolved_facts          = New-Object System.Collections.ArrayList
        failures                = New-Object System.Collections.ArrayList
        stale_facts             = New-Object System.Collections.ArrayList
        disputed_facts          = New-Object System.Collections.ArrayList
        device_identity_mismatch = $false
        record_count            = 0
    }
}

function Add-Fact {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Locator,
        [Parameter(Mandatory)][string]$EvidenceType,
        $Value,
        [hashtable]$Coordinates = @{}
    )
    [void]$Result.resolved_facts.Add([pscustomobject]@{
        fact_locator  = $Locator
        evidence_type = $EvidenceType
        value         = $Value
        coordinates   = $Coordinates
    })
    $Result.record_count = $Result.record_count + 1
}

function Add-Failure {
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Locator,
        [Parameter(Mandatory)][string]$Reason,
        [string]$Detail = ''
    )
    # A collector that stays silent about what it could not read is the exact
    # failure mode this experiment exists to measure. Always record it.
    [void]$Result.failures.Add([pscustomobject]@{
        locator = $Locator
        reason  = $Reason
        detail  = $Detail
    })
}

function Write-CollectorResult {
    param([Parameter(Mandatory)]$Result)
    $Result | ConvertTo-Json -Depth 8 -Compress
}

function Get-ArpEntries {
    # Read Add/Remove Programs entries from one base key in one registry view.
    param(
        [Parameter(Mandatory)][string]$HiveName,   # LocalMachine | CurrentUser | Users
        [Parameter(Mandatory)][string]$ViewName,   # Registry64 | Registry32
        [Parameter(Mandatory)][string]$SubKey,
        [string]$SidPrefix = ''
    )
    $hive = [Microsoft.Win32.RegistryHive]::$HiveName
    $view = [Microsoft.Win32.RegistryView]::$ViewName
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
    try {
        $path = if ($SidPrefix) { "$SidPrefix\$SubKey" } else { $SubKey }
        $root = $base.OpenSubKey($path)
        if ($null -eq $root) { return @() }
        try {
            foreach ($name in $root.GetSubKeyNames()) {
                $child = $root.OpenSubKey($name)
                if ($null -eq $child) { continue }
                try {
                    [pscustomobject]@{
                        key              = "$path\$name"
                        display_name     = $child.GetValue('DisplayName')
                        display_version  = $child.GetValue('DisplayVersion')
                        install_location = $child.GetValue('InstallLocation')
                        registry_view    = $ViewName
                        hive             = $HiveName
                    }
                } finally { $child.Close() }
            }
        } finally { $root.Close() }
    } finally { $base.Close() }
}
