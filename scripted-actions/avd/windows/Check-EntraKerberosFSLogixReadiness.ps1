#description: Readiness check for Entra Kerberos + FSLogix on a session host: client Kerberos keys, FSLogix profile config, cloud Kerberos ticket policy, and hybrid join state. Read-only diagnostic - makes no changes.
#execution mode: Individual
#tags: FSLogix, Entra Kerberos, Identity, Diagnostics

# One-shot readiness check for Entra Kerberos + FSLogix on an AVD session host (SYSTEM context).
# Run after the client-key scripted action + reboot, and after FSLogix profile config.
#
# NOTE: as SYSTEM, klist cloud_debug reports the POLICY state, not a real user's cloud
# ticket. Verify the actual cifs/<storageaccount>.file.core.windows.net ticket with klist
# in a real user session at logon.
#
# NOTE: this only checks host-level state. It does not validate the Azure Files storage
# account's own Kerberos configuration (that requires Azure context - use a runbook action).

$ErrorActionPreference = 'Continue'

$logDir = 'C:\Windows\Temp\NMWLogs\ScriptedActions'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path "$logDir\Check-EntraKerberosFSLogixReadiness-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

$script:failCount = 0

function Format-RegDisplayValue {
    param($Value)
    if ($null -eq $Value) { return '<missing>' }
    if ($Value -is [array]) { return ($Value -join '; ') }
    return "$Value"
}

function Test-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Expected
    )

    $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    $val  = if ($prop) { $prop.$Name } else { $null }

    $isWildcard = ($Expected -eq '*')
    $hasValue   = ($null -ne $val) -and ("$val".Trim() -ne '')
    $ok = if ($isWildcard) { $hasValue } else { $hasValue -and ($val -eq $Expected) }

    if (-not $ok) { $script:failCount++ }

    $display     = Format-RegDisplayValue $val
    $wantDisplay = if ($isWildcard) { 'any non-empty value' } else { $Expected }
    $status      = if ($ok) { 'PASS' } else { 'FAIL' }

    Write-Output ("{0}  {1}\{2} = {3} (want: {4})" -f $status, $Path, $Name, $display, $wantDisplay)
}

Write-Output "=== Entra Kerberos + FSLogix readiness on $env:COMPUTERNAME ==="

Write-Output "`n[1] Client-side Kerberos keys"
Test-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'CloudKerberosTicketRetrievalEnabled' -Expected 1
Test-RegValue -Path 'HKLM:\Software\Policies\Microsoft\AzureADAccount' -Name 'LoadCredKeyFromProfile' -Expected 1

Write-Output "`n[2] FSLogix profile config"
Test-RegValue -Path 'HKLM:\Software\FSLogix\Profiles' -Name 'Enabled' -Expected 1
Test-RegValue -Path 'HKLM:\Software\FSLogix\Profiles' -Name 'VHDLocations' -Expected '*'

Write-Output "`n[3] Cloud Kerberos ticket policy (klist cloud_debug)"
Write-Output "      (SYSTEM context: this reports policy state only, not a real user's cloud ticket)"
$cloudOutput = $null
try {
    $cloudOutput = klist cloud_debug 2>&1
} catch {
    Write-Output "FAIL  klist cloud_debug failed to run: $($_.Exception.Message)"
    $script:failCount++
}

if ($cloudOutput) {
    $policyLine = $cloudOutput | Select-String -Pattern 'enabled by policy' -SimpleMatch | Select-Object -First 1
    if (-not $policyLine) {
        Write-Output "FAIL  No 'enabled by policy' line found in klist cloud_debug output."
        Write-Output "      (OS build/localization may use different wording than expected - raw output below)"
        $cloudOutput | ForEach-Object { Write-Output "      $_" }
        $script:failCount++
    } elseif ($policyLine.Line -match ':\s*0*1\b') {
        Write-Output ("PASS  " + $policyLine.Line.Trim())
    } else {
        Write-Output ("FAIL  " + $policyLine.Line.Trim())
        Write-Output "      Cloud Kerberos ticket policy is not enabled. If the client key was set recently, this host may just need a reboot."
        $script:failCount++
    }
}

Write-Output "`n[4] Hybrid join state"
$aadJoined    = $false
$domainJoined = $false
$dsregParsed  = $false
try {
    $raw = dsregcmd /status 2>&1
    if ($LASTEXITCODE -eq 0 -and $raw) {
        $aadLine = $raw | Where-Object { $_ -match '^\s*AzureAdJoined\s*:' } | Select-Object -First 1
        $domLine = $raw | Where-Object { $_ -match '^\s*DomainJoined\s*:'  } | Select-Object -First 1
        if ($aadLine -and $domLine) {
            $dsregParsed  = $true
            $aadJoined    = [bool]($aadLine -match ':\s*YES\b')
            $domainJoined = [bool]($domLine -match ':\s*YES\b')
            Write-Output ("      " + ($aadLine -replace '\s+',' ').Trim())
            Write-Output ("      " + ($domLine -replace '\s+',' ').Trim())
        }
    }
} catch {
    Write-Output "WARN  dsregcmd /status failed to run: $($_.Exception.Message)"
}

if (-not $dsregParsed) {
    # dsregcmd text can vary by OS build/locale - fall back to a locale-independent check.
    Write-Output "WARN  Could not parse dsregcmd output (build/localization difference?) - falling back to registry/CIM"
    $aadJoined    = [bool](Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue | Select-Object -First 1)
    $domainJoined = [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
    Write-Output ("      AzureAdJoined (registry) : " + $(if ($aadJoined) { 'YES' } else { 'NO' }))
    Write-Output ("      DomainJoined  (CIM)      : " + $(if ($domainJoined) { 'YES' } else { 'NO' }))
}

if ($aadJoined -and $domainJoined) {
    Write-Output "PASS  Hybrid Azure AD joined"
} else {
    Write-Output "WARN  Not both YES (fine for a cloud-only test; hybrid Entra Kerberos requires both YES)"
}

$overall = if ($script:failCount -eq 0) { 'READY' } else { "NOT READY - $($script:failCount) check(s) failed, see FAIL lines above" }
Write-Output "`n=== OVERALL: $overall ==="

Stop-Transcript

if ($script:failCount -gt 0) {
    throw "Entra Kerberos + FSLogix readiness check failed: $($script:failCount) check(s) not ready. See job output above for details."
}
