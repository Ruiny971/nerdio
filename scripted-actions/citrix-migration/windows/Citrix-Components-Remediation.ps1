<#
.SYNOPSIS
    NME Windows scripted action - remove Citrix components (DESTRUCTIVE). MANUAL FALLBACK.

.DESCRIPTION
    Fallback cleanup for Citrix components on an imported Citrix image, so it can serve as
    a clean AVD RemoteApp host.

    PRIMARY ROUTE FIRST. Nerdio removes Citrix during import: tick "Uninstall legacy VDI
    agents" in the Add Image from Azure VM dialog, and use Nerdio's own publisher-based
    Citrix-removal scripted actions. Those are more thorough than this script. Run
    Citrix-PreConversion-Audit.ps1 after the import to see what, if anything, is left.

    Only use this script if that audit shows Citrix components still present - for example
    if the import-time option was missed or left part of the stack behind. It uninstalls
    Profile Management (UPM), the WEM agent, App Layering, the Workspace app, and clears
    leftover services, registry keys and scheduled tasks. It also removes the VDA if it is
    still present.

    Order: the non-VDA components are uninstalled first, then the leftover services,
    registry keys and tasks are cleared, then the VDA is handled last because its
    uninstall can force a reboot.

.IMPORTANT
    - Destructive. Only run on the imported PoC image, never a host that should keep Citrix.
    - SAFETY SWITCH: set $ConfirmRemoval to $true to allow it to run. While $false it does
      a dry run and only reports what it would remove.
    - The script is safe to re-run. If the VDA uninstall forces a reboot and cuts the run
      short, run the script again after the reboot; already-removed items are skipped.
    - After this script and a reboot, run Citrix's own VDA Cleanup Utility for a fully
      clean image.

.NOTES
    Nerdio Manager for Enterprise scripted action. Working draft, lab-test before use.
#>

#description: Remove Citrix components from an imported Citrix image (destructive — set $ConfirmRemoval = $true to act)
#execution mode: Individual
#tags: Citrix, AVD, Migration, Remediation

# === SAFETY SWITCH =========================================================
$ConfirmRemoval = $false   # set to $true to actually uninstall; $false = dry run only
# ===========================================================================

$ErrorActionPreference = 'Continue'
$VerbosePreference     = 'SilentlyContinue'
function Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }

$logDir = 'C:\Windows\Temp\NMWLogs\ScriptedActions'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path "$logDir\Citrix-Components-Remediation-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

# Run one uninstall command and report its real exit code. Logs only; returns nothing.
function Invoke-Uninstall($displayName, $cmd, $productCode) {
    if ($cmd -match '(?i)msiexec') {
        $p = Start-Process 'msiexec.exe' -ArgumentList "/x $productCode /qn /norestart REBOOT=ReallySuppress" -Wait -PassThru -NoNewWindow
    } else {
        # EXE uninstaller: run the vendor's own command as-is via cmd.exe, so quoted
        # paths and the vendor's own silent switches are preserved. No switches invented.
        # NOTE: assumes QuietUninstallString already has paths with spaces quoted —
        # Citrix MSI products do; verify if other products are added to $targets.
        $p = Start-Process 'cmd.exe' -ArgumentList "/c $cmd" -Wait -PassThru -NoNewWindow
    }
    if ($p.ExitCode -in @(0,3010)) {
        Log ("done     : {0} (exit {1})" -f $displayName, $p.ExitCode)
    } else {
        Log ("FAILED   : {0} (exit {1}) - check this component manually" -f $displayName, $p.ExitCode)
    }
}

# Uninstall one app: prefer the vendor quiet string; only act if it can be done silently.
function Uninstall-CitrixApp($app) {
    $quiet = $app.QuietUninstallString
    $cmd   = if ($quiet) { $quiet } else { $app.UninstallString }
    if (-not $cmd) {
        Log ("WARNING  : {0} - no uninstall string found, remove manually" -f $app.DisplayName)
        return
    }
    $isMsi = $cmd -match '(?i)msiexec'
    if (-not $quiet -and -not $isMsi) {
        Log ("WARNING  : {0} - only a non-silent uninstall string; skipping to avoid an interactive hang. Remove manually." -f $app.DisplayName)
        return
    }
    if (-not $ConfirmRemoval) {
        Log ("DRY RUN  : would uninstall {0}  ->  {1}" -f $app.DisplayName, $cmd)
        return
    }
    Log ("uninstall: {0}" -f $app.DisplayName)
    try { Invoke-Uninstall -displayName $app.DisplayName -cmd $cmd -productCode $app.PSChildName }
    catch { Log ("ERROR    : {0} - {1}" -f $app.DisplayName, $_.Exception.Message) }
}

Log ("Citrix component remediation - start.  Mode: {0}" -f $(if ($ConfirmRemoval) {'LIVE UNINSTALL'} else {'DRY RUN'}))

$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$allApps = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }

# --- 1. Non-VDA components (mostly MSI, low reboot risk) -------------------
$targets = @(
    @{ Name = 'WEM Agent';                Match = 'Workspace Environment Management|Norskale' }
    @{ Name = 'Profile Management (UPM)'; Match = 'Citrix Profile Management' }
    @{ Name = 'App Layering';             Match = 'Citrix App Layering|Unidesk' }
    @{ Name = 'Workspace app / Receiver'; Match = 'Citrix Workspace|Citrix Receiver' }
)
foreach ($t in $targets) {
    $apps = $allApps | Where-Object { $_.DisplayName -match $t.Match }
    if (-not $apps) { Log ("skip     : {0} - not installed" -f $t.Name); continue }
    foreach ($app in $apps) { Uninstall-CitrixApp $app }
}

# --- 2. Leftover Citrix services (same filter as the audit) ---------------
Log "Checking for leftover Citrix services..."
$svc = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'Citrix|Norskale' -or $_.DisplayName -match 'Citrix|Norskale' }
foreach ($s in $svc) {
    if (-not $ConfirmRemoval) { Log ("DRY RUN  : would stop and delete service {0}" -f $s.Name); continue }
    try {
        Stop-Service $s.Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $s.Name | Out-Null
        if ($LASTEXITCODE -eq 0) { Log ("removed service: {0}" -f $s.Name) }
        else { Log ("WARNING  : service {0} not deleted (sc.exe exit {1})" -f $s.Name, $LASTEXITCODE) }
    } catch { Log ("ERROR removing service {0}: {1}" -f $s.Name, $_.Exception.Message) }
}

# --- 3. Leftover Citrix registry keys -------------------------------------
foreach ($p in @('HKLM:\SOFTWARE\Policies\Citrix','HKLM:\SOFTWARE\Citrix','HKLM:\SOFTWARE\WOW6432Node\Citrix')) {
    if (-not (Test-Path $p)) { continue }
    if (-not $ConfirmRemoval) { Log ("DRY RUN  : would delete registry key {0}" -f $p); continue }
    try { Remove-Item $p -Recurse -Force -ErrorAction Stop; Log ("removed key: {0}" -f $p) }
    catch { Log ("ERROR removing key {0}: {1}" -f $p, $_.Exception.Message) }
}

# --- 4. Leftover Citrix scheduled tasks (same filter as the audit) --------
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -match 'Citrix' -or $_.TaskPath -match 'Citrix' }
foreach ($task in $tasks) {
    if (-not $ConfirmRemoval) { Log ("DRY RUN  : would delete task {0}{1}" -f $task.TaskPath, $task.TaskName); continue }
    try {
        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false
        Log ("removed task: {0}{1}" -f $task.TaskPath, $task.TaskName)
    } catch { Log ("ERROR removing task: {0}" -f $_.Exception.Message) }
}

# --- 5. VDA last - it can force a reboot ----------------------------------
$vda = $allApps | Where-Object { $_.DisplayName -match 'Virtual Delivery Agent|Virtual Apps and Desktops' }
if (-not $vda) {
    Log "skip     : Virtual Delivery Agent - not installed (expected, the import tickbox removes it)"
} else {
    foreach ($app in $vda) {
        if ($ConfirmRemoval) { Log "Note: the VDA uninstall is last because it may force a reboot." }
        Uninstall-CitrixApp $app
    }
}

# --- Pending reboot check -------------------------------------------------
$rebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

Log "Remediation finished."
if (-not $ConfirmRemoval) {
    Log 'This was a DRY RUN. Review the output, then set $ConfirmRemoval = $true to run for real.'
} else {
    if ($rebootPending) {
        Log "A reboot is pending (likely the VDA uninstall). Reboot, then re-run this script to finish any cleanup that was cut short."
    }
    Log "After the reboot, run Citrix's VDA Cleanup Utility before 'Set as Image'."
}
Stop-Transcript
