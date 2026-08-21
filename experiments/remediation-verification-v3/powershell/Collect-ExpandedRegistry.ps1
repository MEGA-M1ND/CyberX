<#
.SYNOPSIS
  Collector B - expanded registry enumeration across both views and every loaded
  user hive, with its exclusions declared. Read-only.

.DESCRIPTION
  Same family of mechanism as collector A, with roughly ten extra lines: it
  reads both registry views, HKCU, and every loaded HKU SID, and it
  cross-references ProfileList so it can NAME the profiles that exist but are
  not loaded instead of implying they contain nothing.

  That last part is the entire difference between a declared gap and an
  undeclared one, and it is why this collector claims completeness for nothing.
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
    evidence_types      = @('PACKAGE_INVENTORY', 'REGISTRY_VALUE')
    registry_views      = @('Registry64', 'Registry32')
    hives               = @('HKLM', 'HKCU', 'HKU')
    user_scopes         = @('machine', 'current_user', 'other_user_loaded')
    providers           = @('arp_machine', 'arp_wow6432', 'arp_user')
    claims_complete_for = @()
    declared_exclusions = @('other_user_offline', 'none_portable', 'appx', 'msu_package')
    reads_only          = $true
}
$result = New-CollectorResult -CollectorId 'B_EXPANDED_REGISTRY' -Version '1.0.0' -Scope $scope

$subKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
$wowKey = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

function Add-Entries {
    param($Entries, [string]$UserScope)
    foreach ($entry in $Entries) {
        if ($entry.key -notlike "*$ArpPrefix*") { continue }
        Add-Fact -Result $result -Locator $entry.key -EvidenceType 'PACKAGE_INVENTORY' `
                 -Value @{ display_name = $entry.display_name
                           display_version = $entry.display_version
                           install_location = $entry.install_location } `
                 -Coordinates @{ registry_view = $entry.registry_view
                                 hive = $entry.hive; user_scope = $UserScope }
    }
}

foreach ($pair in @(@('Registry64', $subKey), @('Registry32', $wowKey))) {
    try {
        Add-Entries -Entries (Get-ArpEntries -HiveName 'LocalMachine' -ViewName $pair[0] -SubKey $pair[1]) `
                    -UserScope 'machine'
    } catch {
        Add-Failure -Result $result -Locator "HKLM\$($pair[1]) [$($pair[0])]" `
                    -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
    }
}

try {
    Add-Entries -Entries (Get-ArpEntries -HiveName 'CurrentUser' -ViewName 'Registry64' -SubKey $subKey) `
                -UserScope 'current_user'
} catch {
    Add-Failure -Result $result -Locator "HKCU\$subKey" -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
}

# Loaded user hives, then the profiles that exist and are NOT loaded.
$loadedSids = @()
try {
    $usersBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $loadedSids = @($usersBase.GetSubKeyNames() | Where-Object { $_ -like 'S-1-5-21-*' -and $_ -notlike '*_Classes' })
        foreach ($sid in $loadedSids) {
            try {
                Add-Entries -Entries (Get-ArpEntries -HiveName 'Users' -ViewName 'Registry64' `
                                                     -SubKey $subKey -SidPrefix $sid) `
                            -UserScope 'other_user_loaded'
            } catch {
                Add-Failure -Result $result -Locator "HKU\$sid\$subKey" -Reason 'COLLECTION_ERROR' `
                            -Detail $_.Exception.Message
            }
        }
    } finally { $usersBase.Close() }
} catch {
    Add-Failure -Result $result -Locator 'HKU' -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
}

try {
    $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($profile in (Get-ChildItem $profileList -ErrorAction Stop)) {
        $sid = Split-Path $profile.Name -Leaf
        if ($sid -notlike 'S-1-5-21-*') { continue }
        if ($loadedSids -contains $sid) { continue }
        $path = (Get-ItemProperty $profile.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        Add-Failure -Result $result -Locator "HKU\$sid\$subKey" -Reason 'UNLOADED_USER_HIVE' `
                    -Detail "profile $path exists but its hive is not loaded; reading it would " +
                            "require mounting NTUSER.DAT, which is a write to the registry namespace"
    }
} catch {
    Add-Failure -Result $result -Locator 'ProfileList' -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
}

Write-CollectorResult -Result $result
