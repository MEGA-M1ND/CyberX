<#
.SYNOPSIS
  Collector D - targeted filesystem and file-version inspection. Read-only.

.DESCRIPTION
  Enumerates a DECLARED list of roots and reads FileVersionInfo for each match.
  It cannot claim completeness by construction: it only knows about the roots it
  was handed. That limitation is also what makes it honest - and, per the v2
  result, honesty about scope is what a verifier can actually act on.

  -ExtraRoots is how the composite collector widens the search when a decisive
  fact is unresolved, and every widening is recorded in the emitted scope.
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

$defaultRoots = @(
    (Join-Path $FileRoot 'machine64'),
    (Join-Path $FileRoot 'machine32'),
    (Join-Path $FileRoot 'sxs'),
    (Join-Path $FileRoot 'bumped'),
    (Join-Path $FileRoot 'residual'),
    (Join-Path $FileRoot 'services'),
    (Join-Path $FileRoot 'nofile'),
    (Join-Path $FileRoot 'scoped'),
    (Join-Path $FileRoot 'conflict'),
    (Join-Path $FileRoot 'restricted')
)
$widened = @()
if ($ExtraRoots) { $widened = $ExtraRoots -split ',' | Where-Object { $_ } }
$roots = @($defaultRoots) + @($widened)

$scope = @{
    evidence_types      = @('FILE_PRESENCE', 'FILE_VERSION')
    path_roots          = $roots
    default_path_roots  = $defaultRoots
    widened_path_roots  = $widened
    user_scopes         = @('machine', 'current_user', 'other_user_loaded', 'other_user_offline')
    claims_complete_for = @()
    declared_exclusions = @('any path outside path_roots')
    reads_only          = $true
}
$result = New-CollectorResult -CollectorId 'D_FILE_VERSION' -Version '1.0.0' -Scope $scope

foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) {
        Add-Failure -Result $result -Locator $root -Reason 'PATH_NOT_PRESENT' `
                    -Detail 'declared root does not exist on this machine'
        continue
    }
    try {
        $files = Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.exe' -ErrorAction Stop
    } catch [System.UnauthorizedAccessException] {
        Add-Failure -Result $result -Locator $root -Reason 'PERMISSION_DENIED' `
                    -Detail $_.Exception.Message
        continue
    } catch {
        Add-Failure -Result $result -Locator $root -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
        continue
    }
    foreach ($file in $files) {
        try {
            $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
            Add-Fact -Result $result -Locator $file.FullName -EvidenceType 'FILE_VERSION' `
                     -Value @{ file_version = $info.FileVersion
                               product_version = $info.ProductVersion
                               length = $file.Length
                               last_write_utc = $file.LastWriteTimeUtc.ToString('o') } `
                     -Coordinates @{ path_root = $root }
        } catch {
            Add-Failure -Result $result -Locator $file.FullName -Reason 'COLLECTION_ERROR' `
                        -Detail $_.Exception.Message
        }
    }
}

Write-CollectorResult -Result $result
