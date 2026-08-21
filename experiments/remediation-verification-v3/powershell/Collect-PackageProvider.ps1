<#
.SYNOPSIS
  Collector C - PowerShell PackageManagement inventory. Read-only.

.DESCRIPTION
  Get-Package with the Programs provider. Its output is routinely consumed as
  "the software inventory", which is the completeness claim modelled here.

  Win32_Product is deliberately NOT used: enumerating that class triggers an MSI
  consistency check against every registered product, which is write-adjacent
  and outside this experiment's read-only boundary.
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
    evidence_types      = @('PACKAGE_INVENTORY')
    registry_views      = @('Registry64', 'Registry32')
    hives               = @('HKLM', 'HKCU')
    user_scopes         = @('machine', 'current_user')
    providers           = @('arp_machine', 'arp_wow6432', 'arp_user')
    claims_complete_for = @('PACKAGE_INVENTORY')
    declared_exclusions = @()
    reads_only          = $true
    excluded_mechanisms = @('Win32_Product (triggers MSI consistency checks)')
}
$result = New-CollectorResult -CollectorId 'C_PACKAGE_PROVIDER' -Version '1.0.0' -Scope $scope

try {
    $packages = Get-Package -ProviderName Programs -ErrorAction Stop
    foreach ($package in $packages) {
        if ($package.Name -notlike "*$ArpPrefix*" -and $package.Name -notlike '*RV3Lab*') { continue }
        Add-Fact -Result $result -Locator $package.Name -EvidenceType 'PACKAGE_INVENTORY' `
                 -Value @{ display_name = $package.Name
                           display_version = $package.Version
                           source = $package.Source } `
                 -Coordinates @{ user_scope = 'machine' }
    }
} catch {
    Add-Failure -Result $result -Locator 'Get-Package -ProviderName Programs' `
                -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
}

Write-CollectorResult -Result $result
