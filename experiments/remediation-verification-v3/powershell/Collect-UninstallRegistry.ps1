<#
.SYNOPSIS
  Collector A - standard uninstall-registry enumeration. Read-only.

.DESCRIPTION
  The script almost every estate already has: one hive, one view, presented as
  "installed software". It is included precisely because it is ubiquitous and
  because its completeness claim is much wider than its reach.

  It does NOT read the 32-bit view, HKCU, or any other user's hive, and - by
  design of this arm - it does not say so. Compare with Collect-ExpandedRegistry.ps1,
  which is the same mechanism with its exclusions written down.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureId,
    [string]$FileRoot = 'C:\RV3Lab',
    [string]$RegistryRoot = 'SOFTWARE\RV3Lab',
    [string]$ArpPrefix = 'RV3Lab_',
    [string]$ExtraRoots = ''
)

. (Join-Path $PSScriptRoot '_Common.ps1')

$scope = @{
    evidence_types         = @('PACKAGE_INVENTORY')
    registry_views         = @('Registry64')
    hives                  = @('HKLM')
    user_scopes            = @('machine')
    providers              = @('arp_machine')
    claims_complete_for    = @('PACKAGE_INVENTORY')
    declared_exclusions    = @()
    reads_only             = $true
}
$result = New-CollectorResult -CollectorId 'A_UNINSTALL_REGISTRY' -Version '1.0.0' -Scope $scope

$subKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
try {
    foreach ($entry in (Get-ArpEntries -HiveName 'LocalMachine' -ViewName 'Registry64' -SubKey $subKey)) {
        if ($entry.display_name -and $entry.display_name -notlike "$ArpPrefix*" -and
            $entry.key -notlike "*$ArpPrefix*") { continue }
        Add-Fact -Result $result -Locator $entry.key -EvidenceType 'PACKAGE_INVENTORY' `
                 -Value @{ display_name = $entry.display_name
                           display_version = $entry.display_version
                           install_location = $entry.install_location } `
                 -Coordinates @{ registry_view = 'Registry64'; hive = 'HKLM'; user_scope = 'machine' }
    }
} catch {
    Add-Failure -Result $result -Locator $subKey -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
}

Write-CollectorResult -Result $result
