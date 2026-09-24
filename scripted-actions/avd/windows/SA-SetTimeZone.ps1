#description: Sets the OS time zone on a session host. Run against a single VM or a whole host pool from NME's scripted actions.
#execution mode: Individual
#tags: Windows, AVD, TimeZone

<#
$TimeZoneId must match a valid Windows time zone ID exactly (case-sensitive lookup is not required,
but spelling is). Run `tzutil /l` on any Windows box to list valid IDs, e.g.:
  "Eastern Standard Time", "Pacific Standard Time", "GMT Standard Time", "W. Europe Standard Time"
#>
param(
    [string]$TimeZoneId = 'Eastern Standard Time'
)

$ErrorActionPreference = 'Stop'

$logDir = 'C:\Windows\Temp\NMWLogs\ScriptedActions'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path "$logDir\SA-SetTimeZone-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

try {
    Write-Output "Running on: $env:COMPUTERNAME"
    Write-Output "Requested time zone: $TimeZoneId"

    $validIds = (Get-TimeZone -ListAvailable).Id
    if ($validIds -notcontains $TimeZoneId) {
        throw "'$TimeZoneId' is not a valid Windows time zone ID. Run 'tzutil /l' to see valid IDs."
    }

    $before = Get-TimeZone
    Write-Output "Current time zone: $($before.Id)"

    if ($before.Id -eq $TimeZoneId) {
        Write-Output "Time zone already set to '$TimeZoneId'. No change needed."
    }
    else {
        Set-TimeZone -Id $TimeZoneId
        $after = Get-TimeZone
        Write-Output "Time zone changed: $($before.Id) -> $($after.Id)"
    }

    Write-Output "Done. Users should log off and back on for the change to fully apply in their session."
}
catch {
    Write-Output "ERROR: $_"
    throw
}
finally {
    Stop-Transcript
}
