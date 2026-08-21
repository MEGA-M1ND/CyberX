<#
.SYNOPSIS
  Collector E - service and scheduled-task inspection. Read-only.

.DESCRIPTION
  Get-Service and Get-ScheduledTask. This is the one channel whose completeness
  claim its mechanism can actually support: both enumerations are genuinely
  exhaustive at machine scope.

  Startup type is collected alongside current state, because "stopped" and
  "stopped and will stay stopped" are different answers and only the second one
  is remediation.
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
    evidence_types      = @('SERVICE_STATE', 'SCHEDULED_TASK', 'PERSISTENCE_STATE')
    user_scopes         = @('machine', 'current_user')
    claims_complete_for = @('SERVICE_STATE', 'SCHEDULED_TASK', 'PERSISTENCE_STATE')
    declared_exclusions = @()
    reads_only          = $true
}
$result = New-CollectorResult -CollectorId 'E_SERVICE_TASK' -Version '1.0.0' -Scope $scope

try {
    foreach ($service in (Get-Service -ErrorAction Stop | Where-Object { $_.Name -like 'RV3Lab_*' })) {
        $startup = $null
        try {
            $startup = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" `
                        -ErrorAction Stop).StartMode
        } catch {
            Add-Failure -Result $result -Locator $service.Name -Reason 'COLLECTION_ERROR' `
                        -Detail "startup type unavailable: $($_.Exception.Message)"
        }
        Add-Fact -Result $result -Locator $service.Name -EvidenceType 'SERVICE_STATE' `
                 -Value @{ status = [string]$service.Status; startup_type = $startup } `
                 -Coordinates @{ user_scope = 'machine' }
        Add-Fact -Result $result -Locator $service.Name -EvidenceType 'PERSISTENCE_STATE' `
                 -Value @{ startup_type = $startup
                           returns_after_restart = ($startup -eq 'Auto') } `
                 -Coordinates @{ user_scope = 'machine' }
    }
} catch {
    Add-Failure -Result $result -Locator 'Get-Service' -Reason 'COLLECTION_ERROR' -Detail $_.Exception.Message
}

try {
    foreach ($task in (Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -like 'RV3Lab_*' })) {
        $actions = @($task.Actions | ForEach-Object { $_.Execute })
        $triggers = @($task.Triggers | ForEach-Object { $_.CimClass.CimClassName })
        Add-Fact -Result $result -Locator $task.TaskName -EvidenceType 'SCHEDULED_TASK' `
                 -Value @{ state = [string]$task.State; actions = $actions; triggers = $triggers } `
                 -Coordinates @{ user_scope = 'machine' }
    }
} catch {
    Add-Failure -Result $result -Locator 'Get-ScheduledTask' -Reason 'COLLECTION_ERROR' `
                -Detail $_.Exception.Message
}

Write-CollectorResult -Result $result
