<#
.SYNOPSIS
    One-shot readiness check for Entra Kerberos + FSLogix on an AVD session host.

.DESCRIPTION
    NME Windows scripted action (SYSTEM context). Verifies, in one run:
      - CloudKerberosTicketRetrievalEnabled = 1
      - LoadCredKeyFromProfile = 1
      - FSLogix Profiles Enabled = 1 and VHDLocations set
      - Cloud Kerberos enabled by policy (klist cloud_debug)
      - Hybrid join state (dsregcmd)
    Prints a per-item PASS/FAIL and an overall verdict. Run it after the client-key
    scripted action + reboot and after the FSLogix profile is configured.

    #description: Readiness check for Entra Kerberos + FSLogix on a session host (keys, FSLogix, ticket policy, join state)
    #tags: FSLogix, Entra Kerberos, Identity, Diagnostics
#>

$ErrorActionPreference = 'Continue'
$pass = $true

function Test-RegValue {
    param([string]$Path, [string]$Name, $Expected)
    $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    $ok  = ($val -eq $Expected) -or ($Expected -eq '*' -and $null -ne $val -and "$val" -ne '')
    "{0}  {1}\{2} = {3} (want {4})" -f ($(if($ok){'PASS'}else{'FAIL'})), $Path, $Name, $(if($null -eq $val){'<missing>'}else{$val}), $Expected
    if (-not $ok) { $script:pass = $false }
}

Write-Output "=== Entra Kerberos + FSLogix readiness on $env:COMPUTERNAME ==="

Write-Output "`n[1] Client-side Kerberos keys"
Test-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' 'CloudKerberosTicketRetrievalEnabled' 1
Test-RegValue 'HKLM:\Software\Policies\Microsoft\AzureADAccount' 'LoadCredKeyFromProfile' 1

Write-Output "`n[2] FSLogix profile config"
Test-RegValue 'HKLM:\Software\FSLogix\Profiles' 'Enabled' 1
Test-RegValue 'HKLM:\Software\FSLogix\Profiles' 'VHDLocations' '*'

Write-Output "`n[3] Cloud Kerberos ticket policy (klist cloud_debug)"
$cloud = klist cloud_debug 2>$null
$policyLine = $cloud | Select-String -Pattern 'enabled by policy' | Select-Object -First 1
if ($policyLine -and $policyLine.Line -match '1') {
    Write-Output ("PASS  " + $policyLine.Line.Trim())
} else {
    Write-Output ("FAIL  Cloud Kerberos not enabled by policy (needs the key set AND a reboot). " + ($policyLine.Line))
    $pass = $false
}

Write-Output "`n[4] Hybrid join state (dsregcmd)"
$raw = dsregcmd /status
$aad = ($raw | Where-Object { $_ -match '^\s*AzureAdJoined\s*:' } | Select-Object -First 1)
$dom = ($raw | Where-Object { $_ -match '^\s*DomainJoined\s*:' }  | Select-Object -First 1)
Write-Output ("      " + ($aad -replace '\s+',' ').Trim())
Write-Output ("      " + ($dom -replace '\s+',' ').Trim())
if ($aad -match 'YES' -and $dom -match 'YES') { Write-Output "PASS  Hybrid Azure AD joined" }
else { Write-Output "WARN  Not both YES (fine for a cloud-only test; for hybrid, both must be YES)" }

Write-Output "`n=== OVERALL: $(if ($pass) { 'READY' } else { 'NOT READY, see FAIL lines above' }) ==="
