<#
.SYNOPSIS
    NME Windows scripted action - uninstall the SentinelOne agent.

.DESCRIPTION
    Removes the SentinelOne EDR agent from a Windows VM. SentinelOne is anti-tamper
    protected, so the agent removal passphrase is required. The passphrase is read from
    an NME Global Secure Variable, so it is never stored in the script in plain text.

    Intended use: run once against the imported Citrix image (the new Desktop Image VM)
    during a PoC or migration, before "Set as Image". It is NOT meant for production
    session hosts that should keep SentinelOne.

.PREREQUISITES
    - NME Global Secure Variable named:  S1Passphrase
      Value: the SentinelOne removal passphrase, obtained from the customer's security team.
      Note: NME secure variable names are limited to 20 alphanumeric characters,
      which is why the short name S1Passphrase is used.
    - Run as a Windows scripted action (executes on the VM with admin rights).

.NOTES
    SentinelOne's exact uninstall command varies by agent version. This script disables
    anti-tamper with SentinelCtl.exe, then uninstalls via the registered MSI. Confirm the
    approach against the customer's actual agent version before relying on it.

    This image is a CLONE of the Citrix server, so its agent carries the original server's
    SentinelOne identity. Local removal with the passphrase (this script) is the reliable
    route; a console-side removal is not, because the cloned agent may collide with the
    original server's record in the SentinelOne console. Run this early on the imported
    image, and give the customer's security team a heads-up so a cloned-agent alert is
    not a surprise.

    Nerdio Manager for Enterprise scripted action. Working draft, lab-test before use.
#>

#description: Uninstall SentinelOne EDR agent from an imported Citrix image
#execution mode: Individual
#tags: Security, SentinelOne, Migration, Citrix

param(
    # NME injects Global Secure Variables into this parameter (documented NME pattern
    # for Windows scripted actions). Confirm on the lab that the variable resolves.
    [Parameter(ParameterSetName = "NME_PARAMETER")]
    [object]$SecureVars
)

$ErrorActionPreference = 'Stop'
$logDir = 'C:\Windows\Temp\NMWLogs\ScriptedActions'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path "$logDir\Uninstall-SentinelOne-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append
function Log($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }

Log "SentinelOne uninstall - start."

# --- 1. Passphrase from the NME Global Secure Variable ----------------------
$passphrase = $SecureVars.S1Passphrase
if ([string]::IsNullOrWhiteSpace($passphrase)) {
    Log "ERROR: Global Secure Variable 'S1Passphrase' is empty or not set. Aborting."
    exit 1
}

# --- 2. Locate the SentinelOne agent ---------------------------------------
$agentRoot = 'C:\Program Files\SentinelOne'
if (-not (Test-Path $agentRoot)) {
    Log "SentinelOne does not appear to be installed (no $agentRoot). Nothing to do."
    exit 0
}
# Pick the newest agent folder by parsed version, not a plain string sort.
$agentDir = Get-ChildItem -Path $agentRoot -Directory -Filter 'Sentinel Agent*' |
    Sort-Object {
        $v = ($_.Name -replace '[^0-9.]', '').Trim('.')
        if ($v -as [version]) { [version]$v } else { [version]'0.0' }
    } -Descending | Select-Object -First 1
if (-not $agentDir) {
    Log "ERROR: No 'Sentinel Agent' folder found under $agentRoot. Aborting."
    exit 1
}
$sentinelCtl = Join-Path $agentDir.FullName 'SentinelCtl.exe'
if (-not (Test-Path $sentinelCtl)) {
    Log "ERROR: SentinelCtl.exe not found in $($agentDir.FullName). Aborting."
    exit 1
}
Log "Found agent: $($agentDir.FullName)"

# --- 3. Disable anti-tamper with the passphrase ----------------------------
# Note: the passphrase is passed as a command-line argument, so it is briefly
# visible in the process list. This is unavoidable with SentinelCtl.exe.
Log "Disabling anti-tamper (SentinelCtl unprotect)..."
$unprotect = Start-Process -FilePath $sentinelCtl -ArgumentList @('unprotect','-k',$passphrase) -Wait -PassThru -NoNewWindow
if ($unprotect.ExitCode -ne 0) {
    Log "ERROR: unprotect failed with exit code $($unprotect.ExitCode). The passphrase may be wrong."
    Log "Fallback: have the customer's security team remove the agent from the SentinelOne console."
    exit 1
}
Log "Anti-tamper disabled."

# --- 4. Uninstall via the registered MSI -----------------------------------
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$s1 = Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -like 'Sentinel Agent*' } | Select-Object -First 1
if (-not $s1) {
    Log "WARNING: No 'Sentinel Agent' entry in the uninstall registry. Manual removal may be needed."
    exit 1
}

$productCode = $s1.PSChildName
Log "Uninstalling $($s1.DisplayName) ($productCode)..."
$msiArgs = "/x $productCode /qn /norestart REBOOT=ReallySuppress"
$msi = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow

# msiexec: 0 = success, 3010 = success, reboot required
if ($msi.ExitCode -in @(0,3010)) {
    Log "SentinelOne uninstall completed (msiexec exit $($msi.ExitCode))."
    Log "A reboot is recommended before 'Set as Image'."
    exit 0
} else {
    Log "ERROR: msiexec uninstall failed with exit code $($msi.ExitCode)."
    Log "Fallback: have the customer's security team remove the agent from the SentinelOne console."
    exit 1
}
