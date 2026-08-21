<#
.SYNOPSIS
  Collector F - composite active collector. Read-only.

.DESCRIPTION
  Runs the registry, package, file and service channels, reconciles them, and
  then does the thing no single passive channel does: when a decisive fact is
  still unresolved, it re-queries with a widened scope.

  Two rules it does not break:
    * It claims completeness for nothing. It reports per-fact resolution and
      names what it could not settle.
    * It never mounts an unloaded user hive. Reading one means `reg load` of
      NTUSER.DAT, which mutates the live registry namespace, so an unloaded
      profile stays a declared gap rather than becoming a write.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FixtureId,
    [string]$FileRoot = 'C:\RV3Lab',
    [string]$RegistryRoot = 'SOFTWARE\RV3Lab',
    [string]$ArpPrefix = 'RV3Lab_',
    [string]$ExtraRoots = '',
    [int]$MaxWidenings = 3
)

. (Join-Path $PSScriptRoot '_Common.ps1')

$scope = @{
    evidence_types      = @('PACKAGE_INVENTORY', 'REGISTRY_VALUE', 'FILE_PRESENCE',
                            'FILE_VERSION', 'SERVICE_STATE', 'SCHEDULED_TASK', 'PERSISTENCE_STATE')
    registry_views      = @('Registry64', 'Registry32')
    hives               = @('HKLM', 'HKCU', 'HKU')
    user_scopes         = @('machine', 'current_user', 'other_user_loaded')
    claims_complete_for = @()
    declared_exclusions = @('other_user_offline (requires mounting NTUSER.DAT, which is a write)')
    reads_only          = $true
    max_widenings       = $MaxWidenings
}
$result = New-CollectorResult -CollectorId 'F_COMPOSITE_ACTIVE' -Version '1.0.0' -Scope $scope
$widenings = New-Object System.Collections.ArrayList

$channels = @(
    'Collect-ExpandedRegistry.ps1',
    'Collect-PackageProvider.ps1',
    'Collect-FileVersions.ps1',
    'Collect-ServicesAndTasks.ps1'
)

function Invoke-Channel {
    param([string]$Script, [string]$Extra = '')
    $args = @('-FixtureId', $FixtureId, '-FileRoot', $FileRoot,
              '-RegistryRoot', $RegistryRoot, '-ArpPrefix', $ArpPrefix)
    if ($Extra) { $args += @('-ExtraRoots', $Extra) }
    $json = & (Join-Path $PSScriptRoot $Script) @args
    return $json | ConvertFrom-Json
}

foreach ($script in $channels) {
    try {
        $child = Invoke-Channel -Script $script
        foreach ($fact in $child.resolved_facts) {
            Add-Fact -Result $result -Locator $fact.fact_locator -EvidenceType $fact.evidence_type `
                     -Value $fact.value -Coordinates @{ source_collector = $child.collector_id }
        }
        foreach ($failure in $child.failures) {
            Add-Failure -Result $result -Locator $failure.locator -Reason $failure.reason `
                        -Detail "$($child.collector_id): $($failure.detail)"
        }
    } catch {
        Add-Failure -Result $result -Locator $script -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
    }
}

# Bounded widening: retry the file channel over roots the default list omits,
# one root class per request, up to the cap.
$candidateRoots = @(
    (Join-Path $FileRoot 'portable'),
    (Join-Path $FileRoot 'odd'),
    (Join-Path $FileRoot 'unregistered'),
    (Join-Path $FileRoot 'recreated'),
    (Join-Path $FileRoot 'peruser'),
    (Join-Path $FileRoot 'otheruser')
)
$unresolvedRoots = @($candidateRoots | Where-Object {
    (Test-Path -LiteralPath $_) -and
    -not ($result.resolved_facts | Where-Object { $_.fact_locator -like "$_*" })
})

$used = 0
foreach ($root in $unresolvedRoots) {
    if ($used -ge $MaxWidenings) {
        [void]$widenings.Add([pscustomobject]@{ root = $root; granted = $false
                                                reason = 'WIDENING_BUDGET_EXHAUSTED' })
        continue
    }
    $used = $used + 1
    try {
        $child = Invoke-Channel -Script 'Collect-FileVersions.ps1' -Extra $root
        $added = 0
        foreach ($fact in $child.resolved_facts) {
            if ($fact.fact_locator -notlike "$root*") { continue }
            Add-Fact -Result $result -Locator $fact.fact_locator -EvidenceType $fact.evidence_type `
                     -Value $fact.value -Coordinates @{ source_collector = 'D_FILE_VERSION'
                                                        widened = $true }
            $added = $added + 1
        }
        [void]$widenings.Add([pscustomobject]@{ root = $root; granted = $true; facts_added = $added })
    } catch {
        [void]$widenings.Add([pscustomobject]@{ root = $root; granted = $false
                                                reason = $_.Exception.Message })
    }
}

$result | Add-Member -NotePropertyName widenings -NotePropertyValue $widenings
Write-CollectorResult -Result $result
