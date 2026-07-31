<#
.SYNOPSIS
    Reports whether the AVD session host is Hybrid Azure AD joined.

.DESCRIPTION
    NME Windows scripted action. Runs on the session host in SYSTEM context, where
    dsregcmd's Device State (AzureAdJoined / DomainJoined) is populated. Hybrid joined
    means both are YES. Prints a clear verdict plus the key lines for a screenshot.

    #description: Check Hybrid Azure AD join state (dsregcmd) on the session host
    #tags: Identity, Hybrid Join, Diagnostics
#>

$ErrorActionPreference = 'Stop'

$raw = dsregcmd /status

function Get-DsregValue {
    param([string]$Name)
    $line = $raw | Where-Object { $_ -match "^\s*$Name\s*:" } | Select-Object -First 1
    if ($line) { ($line -split ':', 2)[1].Trim() } else { 'NOT FOUND' }
}

$aadJoined    = Get-DsregValue 'AzureAdJoined'
$domainJoined = Get-DsregValue 'DomainJoined'
$enterprise   = Get-DsregValue 'EnterpriseJoined'
$tenantName   = Get-DsregValue 'TenantName'
$deviceId     = Get-DsregValue 'DeviceId'

Write-Output "=== Hybrid join check on $env:COMPUTERNAME ==="
Write-Output "AzureAdJoined    : $aadJoined"
Write-Output "DomainJoined     : $domainJoined"
Write-Output "EnterpriseJoined : $enterprise"
Write-Output "TenantName       : $tenantName"
Write-Output "DeviceId         : $deviceId"
Write-Output ""

if ($aadJoined -eq 'YES' -and $domainJoined -eq 'YES') {
    Write-Output "RESULT: HYBRID AZURE AD JOINED. Both AzureAdJoined and DomainJoined are YES. Good to go."
}
elseif ($domainJoined -eq 'YES' -and $aadJoined -eq 'NO') {
    Write-Output "RESULT: DOMAIN JOINED ONLY. Hybrid registration has not completed yet."
    Write-Output "Next: wait for an Entra Connect sync cycle (about 30 min), reboot, and re-run. If it stays NO, the computer OU may not be in Entra Connect sync scope."
}
elseif ($aadJoined -eq 'YES' -and $domainJoined -eq 'NO') {
    Write-Output "RESULT: ENTRA JOINED ONLY (cloud-only). This is NOT the hybrid pivot. Check the NME directory profile is the Active Directory type, not native Entra ID."
}
else {
    Write-Output "RESULT: NOT JOINED as expected (AzureAdJoined=$aadJoined, DomainJoined=$domainJoined). Investigate the domain join and network path to a domain controller."
}

Write-Output ""
Write-Output "--- dsregcmd /status (key lines) ---"
$raw | Select-String -Pattern 'AzureAdJoined|DomainJoined|EnterpriseJoined|TenantName|DeviceId' |
    ForEach-Object { Write-Output $_.Line }
