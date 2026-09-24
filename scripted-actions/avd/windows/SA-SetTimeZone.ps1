#description: Sets the OS time zone on a session host. Run against a single VM or a whole host pool from NME's scripted actions. No restart required - Set-TimeZone applies immediately; users just need to log off/back on to see it in their session.
#execution mode: Individual
#tags: Windows, AVD, TimeZone

<#variables:
{
  "TimeZoneId": {
    "Description": "Exact Windows time zone ID (run 'tzutil /l' on any Windows box to list valid IDs), e.g. Romance Standard Time, Eastern Standard Time, GMT Standard Time, W. Europe Standard Time",
    "DisplayName": "Time Zone ID"
  }
}
#>

param(
    [string]$TimeZoneId = 'Romance Standard Time'
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
