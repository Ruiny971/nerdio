<#
.SYNOPSIS
    NME Windows scripted action - Citrix pre-conversion audit (READ ONLY).

.DESCRIPTION
    Inventories Citrix components on the imported Citrix image before it is converted to
    an AVD RemoteApp host. Reports only; it changes nothing. Use the report to decide
    what the remediation script (Citrix-Components-Remediation.ps1) needs to remove.

    Run against the new Desktop Image VM after import, before "Set as Image".

.OUTPUT
    A structured report in the scripted action log: installed Citrix programs, Citrix
    services, Citrix registry policy keys, Citrix scheduled tasks, Citrix display drivers,
    and the OS edition.

.NOTES
    The Citrix service and scheduled-task filters here match the remediation script, so
    the audit reports the same set the remediation script will act on.

    Nerdio Manager for Enterprise scripted action. Working draft, lab-test before use.
#>

#description: Citrix pre-conversion inventory audit — read-only
#execution mode: Individual
#tags: Citrix, AVD, Migration, Audit

$ErrorActionPreference = 'Continue'
$VerbosePreference     = 'SilentlyContinue'   # NME may turn verbose on; keep CIM chatter out of the log
function Section($t) { Write-Output ""; Write-Output ("=== {0} ===" -f $t) }
function Log($m)     { Write-Output $m }

$logDir = 'C:\Windows\Temp\NMWLogs\ScriptedActions'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path "$logDir\Citrix-PreConversion-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

Write-Output "Citrix pre-conversion audit - $(Get-Date -Format 'yyyy-MM-dd HH:mm') - READ ONLY"

# --- OS edition ------------------------------------------------------------
Section "Operating system"
$os = Get-CimInstance Win32_OperatingSystem
Log ("Caption : {0}" -f $os.Caption)
Log ("Version : {0}  Build {1}" -f $os.Version, $os.BuildNumber)
Log "Note: the RemoteApp target is multi-session. Confirm this edition matches."

# --- Installed Citrix programs --------------------------------------------
Section "Installed Citrix programs"
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$citrixApps = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match 'Citrix|Norskale|Unidesk' } |
    Select-Object DisplayName, DisplayVersion, Publisher, PSChildName
if ($citrixApps) {
    $citrixApps | ForEach-Object { Log (" - {0}  [{1}]  {2}" -f $_.DisplayName, $_.DisplayVersion, $_.PSChildName) }
} else {
    Log " (none found)"
}

# Flag the components that matter most for an AVD conversion
Section "Key components to watch"
$watch = @{
    'Virtual Delivery Agent (VDA)' = 'Virtual Delivery Agent|Virtual Apps and Desktops'
    'Profile Management (UPM)'     = 'Citrix Profile Management'
    'WEM Agent'                    = 'Workspace Environment Management|Norskale'
    'App Layering'                 = 'Citrix App Layering|Unidesk'
    'Workspace app / Receiver'     = 'Citrix Workspace|Citrix Receiver'
}
foreach ($k in $watch.Keys) {
    $hit = $citrixApps | Where-Object { $_.DisplayName -match $watch[$k] }
    if ($hit) { Log (" PRESENT : {0}  ->  {1}" -f $k, ($hit.DisplayName -join ', ')) }
    else      { Log (" absent  : {0}" -f $k) }
}
Log "UPM conflicts with FSLogix and must be removed. WEM and HDX redirection should also go."

# --- Citrix services -------------------------------------------------------
Section "Citrix services"
$svc = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'Citrix|Norskale' -or $_.DisplayName -match 'Citrix|Norskale' }
if ($svc) { $svc | ForEach-Object { Log (" - {0}  ({1})  [{2}]" -f $_.DisplayName, $_.Name, $_.Status) } }
else      { Log " (none found)" }

# --- Citrix registry keys --------------------------------------------------
Section "Citrix registry keys"
foreach ($p in @('HKLM:\SOFTWARE\Citrix','HKLM:\SOFTWARE\Policies\Citrix','HKLM:\SOFTWARE\WOW6432Node\Citrix')) {
    if (Test-Path $p) { Log (" PRESENT : {0}" -f $p) } else { Log (" absent  : {0}" -f $p) }
}

# --- Citrix scheduled tasks ------------------------------------------------
Section "Citrix scheduled tasks"
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -match 'Citrix' -or $_.TaskPath -match 'Citrix' }
if ($tasks) { $tasks | ForEach-Object { Log (" - {0}{1}" -f $_.TaskPath, $_.TaskName) } }
else        { Log " (none found)" }

# --- Citrix display / mirror drivers --------------------------------------
Section "Citrix drivers"
try {
    $drv = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.DeviceName -match 'Citrix' -or $_.Manufacturer -match 'Citrix' }
    if ($drv) { $drv | ForEach-Object { Log (" - {0}  ({1})" -f $_.DeviceName, $_.DriverVersion) } }
    else      { Log " (none found)" }
} catch { Log " (driver query not available on this OS)" }

Write-Output ""
Write-Output "=== Audit complete - nothing was changed ==="
Write-Output "Next: review the PRESENT items. Nerdio's import-time removal handles the uninstall; Citrix-Components-Remediation.ps1 is the manual fallback if anything is left."
Stop-Transcript
