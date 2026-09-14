<#
.SYNOPSIS
    Tests an AVD session host VM for OS-level policies that may block Nerdio
    Manager for Enterprise (NME) automation.

.DESCRIPTION
    Captures the OS-level policy and security state of an AVD-candidate VM
    so we can identify potential blockers before NME provisions session hosts.
    Outputs a single ZIP file containing:
      - A transcript with all check results
      - A Group Policy HTML report
      - AppLocker XML if applicable

    Run as Administrator on a VM that is in scope of the same Intune device
    group, GPO, and EDR policy as future NME-managed AVD hosts.

    Note: this script tests the SESSION HOST side. It is different from
    Nerdio's Start-NerdioManagerPreFlight.ps1 (which tests Azure subscription
    readiness pre-deployment) and NmeNetworkTest.ps1 (which runs in the NME
    App Service Kudu console).

    This is a standalone manual diagnostic - NOT an NME Scripted Action. It has
    no NME #variables block and is meant to be run directly on a candidate VM,
    often before that VM is even under NME management, so its output can be
    handed to a customer's EDR/network admin as a portable artifact.

.PARAMETER TestConnectivity
    If specified, also runs outbound connectivity tests against the standard
    set of Microsoft / Nerdio endpoints used by AVD session hosts and captures
    the SSL certificate issuer for each. A non-Microsoft issuer (e.g. Zscaler
    or another proxy CA) on a Microsoft endpoint indicates SSL inspection is
    intercepting the traffic, which will break NME and AVD agents.
    Skip this on environments where outbound is not yet open - it will simply
    return failures and add no signal.

.PARAMETER OutputPath
    The base directory where the output folder and ZIP file will be written.
    Defaults to C:\Temp. Use this on hardened VMs where C:\Temp is restricted.

.EXAMPLE
    .\Test-AvdHostReadiness.ps1
    Runs the policy diagnostic only, outputs to C:\Temp.

.EXAMPLE
    .\Test-AvdHostReadiness.ps1 -TestConnectivity
    Runs the policy diagnostic plus the outbound connectivity / SSL inspection check.

.EXAMPLE
    .\Test-AvdHostReadiness.ps1 -OutputPath "$env:USERPROFILE\Desktop"
    Writes output to the current user's Desktop instead of C:\Temp.

.NOTES
    Requires PowerShell 5.1+ and local Administrator rights.
    The script reads state only and does not modify the VM.
#>

[CmdletBinding()]
param(
    [switch]$TestConnectivity,
    [string]$OutputPath = "C:\Temp"
)

$ErrorActionPreference = 'Continue'

# ---------- Setup ----------
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$workDir   = Join-Path $OutputPath "avd_host_readiness_$timestamp"
$logFile   = Join-Path $workDir "diagnostic.txt"
$gpoFile   = Join-Path $workDir "gpo_report.html"
$zipFile   = Join-Path $OutputPath "avd_host_readiness_$timestamp.zip"

try {
    New-Item -Path $workDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Host "ERROR: cannot create output directory $workDir"
    Write-Host "Try -OutputPath `"`$env:USERPROFILE\Desktop`" instead."
    Write-Host $_.Exception.Message
    exit 1
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70)
    Write-Host "  $Title"
    Write-Host ("=" * 70)
}

function Write-SubSection {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---"
}

Start-Transcript -Path $logFile -Force | Out-Null

Write-Host "AVD Host Readiness Test (NME pre-flight)"
Write-Host "Run time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "User: $env:USERDOMAIN\$env:USERNAME"
Write-Host "Output path: $OutputPath"
Write-Host "Connectivity test: $($TestConnectivity.IsPresent)"
Write-Host ""

# ---------- 0. Elevation check ----------
Write-Section "0. Elevation check"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "Running as Administrator: YES"
} else {
    Write-Host "Running as Administrator: NO"
    Write-Host "WARNING: some checks will return incomplete data without elevation. Re-run as admin for a full picture."
}

# ---------- 1. System context ----------
Write-Section "1. System context"
Write-SubSection "OS"
Get-CimInstance -ClassName Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime |
    Format-List

Write-SubSection "PowerShell version"
[PSCustomObject]@{
    PSVersion       = $PSVersionTable.PSVersion.ToString()
    PSEdition       = $PSVersionTable.PSEdition
    CLRVersion      = $PSVersionTable.CLRVersion
    BuildVersion    = $PSVersionTable.BuildVersion
} | Format-List

Write-SubSection "Domain join state"
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
[PSCustomObject]@{
    Domain         = $cs.Domain
    PartOfDomain   = $cs.PartOfDomain
    DomainRole     = $cs.DomainRole
    Workgroup      = $cs.Workgroup
} | Format-List

Write-SubSection "Azure AD join state (dsregcmd)"
try {
    $dsreg = & dsregcmd /status 2>&1 | Out-String
    $dsreg
} catch {
    Write-Host "dsregcmd not available or failed: $_"
}

Write-SubSection "Pending reboot indicators"
Write-Host "If any of these are TRUE, some queries below may return stale state."
$pendingPaths = @(
    @{ Name = "Component-Based Servicing pending"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" }
    @{ Name = "Windows Update auto-update reboot required"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" }
    @{ Name = "Pending file rename"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"; Value = "PendingFileRenameOperations" }
)
foreach ($p in $pendingPaths) {
    if ($p.Value) {
        $exists = $null -ne (Get-ItemProperty -Path $p.Path -Name $p.Value -ErrorAction SilentlyContinue).$($p.Value)
    } else {
        $exists = Test-Path $p.Path
    }
    Write-Host ("  {0}: {1}" -f $p.Name, $exists)
}
$ccm = $false
try {
    $ccm = (Invoke-CimMethod -Namespace "ROOT\ccm\ClientSDK" -ClassName "CCM_ClientUtilities" -MethodName "DetermineIfRebootPending" -ErrorAction Stop).RebootPending
} catch {}
Write-Host ("  ConfigMgr client reports reboot pending: {0}" -f $ccm)

Write-SubSection "Time sync state"
Write-Host "Note: skewed clocks cause TLS handshake failures that look like SSL inspection."
try {
    $w32 = & w32tm /query /status 2>&1 | Out-String
    $w32
} catch {
    Write-Host "w32tm /query /status failed: $_"
}

# ---------- 2. EDR / SentinelOne ----------
Write-Section "2. EDR agents (SentinelOne, CrowdStrike, others)"
Write-Host "Note: third-party EDR policy is configured centrally in the EDR console."
Write-Host "This section confirms agent state on the VM only. Policy review must"
Write-Host "happen with the EDR admin, see end of report."
Write-Host ""

Write-SubSection "SentinelOne services"
Get-Service SentinelAgent, SentinelStaticEngine, SentinelHelperService -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-SubSection "SentinelOne registry info"
Get-ItemProperty "HKLM:\SOFTWARE\Sentinel Labs\Sentinel Agent" -ErrorAction SilentlyContinue |
    Select-Object * -ExcludeProperty PS* | Format-List

Write-SubSection "SentinelCtl status"
$sctl = Get-ChildItem "C:\Program Files\SentinelOne" -Recurse -Filter "SentinelCtl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sctl) {
    & $sctl.FullName status 2>&1 | Out-String
} else {
    Write-Host "SentinelCtl.exe not found - SentinelOne may not be installed."
}

Write-SubSection "Recent local SentinelOne threats (if SentinelCtl supports threat_list)"
if ($sctl) {
    & $sctl.FullName threat_list 2>&1 | Select-Object -First 50 | Out-String
}

Write-SubSection "Other common EDR services"
Get-Service CSFalconService, CSAgent, ekrn, ESET*, McAfee*, Trellix*, Cybereason*, CarbonBlack*, MsSense -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-SubSection "Symantec Endpoint Protection"
Write-Host "SepMasterService is the current service (ccSvcHst.exe). Smc/SmcService is legacy only -"
Write-Host "on SEP 12.1 RU5+ / modern Endpoint Security, smc runs as a DLL inside SepMasterService, not a standalone service."
Get-Service SepMasterService, Smc, SmcService -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-SubSection "Cortex XDR / Traps"
Write-Host "cyserver is the current, single consolidated agent service (since agent 7.6)."
Write-Host "CyveraService/tlaservice/twdservice are legacy - only present on older agent builds."
Write-Host "cyverak/cyvrmtgn/cyvrfsfd are the kernel driver services."
Get-Service cyserver, CyveraService, tlaservice, twdservice, cyverak, cyvrmtgn, cyvrfsfd -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-SubSection "Other vendors - prefix wildcard match (exact service short names not confirmed)"
Write-Host "Sophos, Cisco Secure Endpoint, Bitdefender, Trend Micro, Cylance, FortiEDR, Elastic, and Malwarebytes"
Write-Host "register services under their own vendor-prefixed short names, but the exact suffix varies by version -"
Write-Host "this matches on the vendor prefix the same way the ESET*/McAfee*/Trellix* checks above do."
Get-Service Sophos*, CiscoAMP*, "AMP*", Bitdefender*, "Trend Micro*", Cylance*, FortiEDR*, Elastic*, Malwarebytes* -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-SubSection "Generic EDR/AV vendor sweep (DisplayName match)"
Write-Host "Catches any product whose exact service short name isn't hardcoded above."
Get-Service | Where-Object {
    $_.DisplayName -match 'Symantec|Broadcom|Cortex|Traps|Palo Alto|Sophos|Trend Micro|Bitdefender|Cylance|BlackBerry|Fortinet|FortiEDR|Secure Endpoint|AMP for Endpoints|Elastic Endpoint|Malwarebytes|Deep Instinct|Cybereason|Carbon ?Black|VMware Carbon'
} | Format-Table Name, DisplayName, Status, StartType -AutoSize

# ---------- 3. Defender / MDE ----------
Write-Section "3. Microsoft Defender / MDE state"
Write-Host "Note: third-party EDR typically disables Defender. Some enterprises run MDE in"
Write-Host "EDR-only mode alongside another EDR. Worth confirming."
Write-Host ""

Write-SubSection "Defender services"
Get-Service WinDefend, WdNisSvc, Sense, MsMpSvc -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-SubSection "Defender computer status (via WMI)"
try {
    Get-CimInstance -Namespace root\Microsoft\Windows\Defender -ClassName MSFT_MpComputerStatus -ErrorAction Stop |
        Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
                      OnAccessProtectionEnabled, IsTamperProtected,
                      AMEngineVersion, AMProductVersion |
        Format-List
} catch {
    Write-Host "Defender WMI provider not available (typical when third-party EDR is in control): $_"
}

Write-SubSection "Get-MpPreference (will fail if Defender disabled)"
try {
    $mp = Get-MpPreference -ErrorAction Stop
    Write-Host "ASR rule IDs and actions:"
    $ids = $mp.AttackSurfaceReductionRules_Ids
    $actions = $mp.AttackSurfaceReductionRules_Actions
    if ($ids -and $ids.Count -gt 0) {
        for ($i = 0; $i -lt $ids.Count; $i++) {
            Write-Host ("  {0} = action {1}" -f $ids[$i], $actions[$i])
        }
        Write-Host ""
        Write-Host "Action key: 0=Disabled, 1=Block, 2=Audit, 6=Warn"
        Write-Host "ASR rules of concern for NME:"
        Write-Host "  5BEB7EFE-FD9A-4556-801D-275E5FFC04CC = Block obfuscated scripts"
        Write-Host "  D1E49AAC-8F56-4280-B9BA-993A6D77406C = Block PSExec/WMI process creation"
        Write-Host "  9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 = Block credential stealing from LSASS"
    } else {
        Write-Host "  No ASR rules configured"
    }
    Write-Host ""
    Write-Host "ASR per-rule exclusions:"
    if ($mp.AttackSurfaceReductionOnlyExclusions) {
        $mp.AttackSurfaceReductionOnlyExclusions | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  None"
    }
    Write-Host ""
    Write-Host "Defender exclusion paths:"
    if ($mp.ExclusionPath) {
        $mp.ExclusionPath | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  None"
    }
    Write-Host ""
    Write-Host "Defender exclusion processes:"
    if ($mp.ExclusionProcess) {
        $mp.ExclusionProcess | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "  None"
    }
    Write-Host ""
    Write-Host ("Controlled Folder Access: {0}" -f $mp.EnableControlledFolderAccess)
    Write-Host ("Tamper Protection: {0}" -f $mp.IsTamperProtected)
} catch {
    Write-Host "Get-MpPreference failed: $($_.Exception.Message)"
    Write-Host "This is expected if a third-party EDR has disabled the Defender stack."
}

# ---------- 4. Registered AV / Security products ----------
Write-Section "4. Registered security products (Windows Security Center)"
try {
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop |
        Select-Object displayName, productState, pathToSignedProductExe, timestamp |
        Format-List
} catch {
    Write-Host "Security Center query failed: $_"
}

# ---------- 5. WDAC ----------
Write-Section "5. WDAC (Windows Defender Application Control)"
Write-SubSection "PowerShell language mode (CRITICAL)"
$lang = $ExecutionContext.SessionState.LanguageMode
Write-Host "Current session language mode: $lang"
if ($lang -ne 'FullLanguage') {
    Write-Host ""
    Write-Host "WARNING: Language mode is NOT FullLanguage."
    Write-Host "NME scripted actions WILL fail with dot-sourcing errors."
    Write-Host "Reference: Nerdio community post on WDAC script enforcement."
}

Write-SubSection "Active WDAC policies (CiTool)"
try {
    & CiTool.exe --list-policies 2>&1 | Out-String
} catch {
    Write-Host "CiTool not available on this OS: $_"
}

Write-SubSection "Recent CodeIntegrity script-block events (last 100)"
$ciEvents = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 3076, 3077, 3089 }
if ($ciEvents) {
    $ciEvents | Select-Object TimeCreated, Id, LevelDisplayName, @{n='Summary';e={ ($_.Message -split "`n")[0] }} |
        Format-Table -AutoSize -Wrap
} else {
    Write-Host "No script-block events found in CodeIntegrity log (good sign)."
}

# ---------- 6. PowerShell Execution Policy ----------
Write-Section "6. PowerShell Execution Policy"
Write-SubSection "Per-scope policy"
Get-ExecutionPolicy -List | Format-Table -AutoSize

$effective = Get-ExecutionPolicy
Write-Host "Effective policy: $effective"
if ($effective -in 'AllSigned', 'Restricted') {
    Write-Host ""
    Write-Host "WARNING: Effective execution policy is $effective."
    Write-Host "Unsigned PowerShell will be blocked. NME scripted actions will fail unless"
    Write-Host "scripts are signed with a certificate trusted on this VM."
}

# ---------- 7. AppLocker ----------
Write-Section "7. AppLocker"
try {
    $applocker = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
    if ($applocker) {
        Write-Host "Effective AppLocker rule collections in force:"
        ($applocker | Select-String "<RuleCollection Type" -AllMatches).Matches |
            ForEach-Object { Write-Host "  $($_.Value)" }
        Write-Host ""
        Write-Host "Full AppLocker XML saved to: applocker_policy.xml"
        $applocker | Out-File -FilePath (Join-Path $workDir "applocker_policy.xml") -Encoding utf8
    } else {
        Write-Host "No effective AppLocker policy."
    }
} catch {
    Write-Host "AppLocker query failed: $_"
}

# ---------- 8. Credential Guard / VBS / LSA Protection ----------
Write-Section "8. Credential Guard / VBS / LSA Protection"
try {
    Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop |
        Select-Object SecurityServicesConfigured, SecurityServicesRunning,
                      CodeIntegrityPolicyEnforcementStatus,
                      UserModeCodeIntegrityPolicyEnforcementStatus,
                      VirtualizationBasedSecurityStatus |
        Format-List
    Write-Host "SecurityServices reference: 1=Credential Guard, 2=HVCI, 3=System Guard Secure Launch, 4=SMM Firmware Measurement, 7=Hypervisor-enforced Paging Translation, 8=KMCI"
} catch {
    Write-Host "Device Guard WMI query failed: $_"
}

Write-SubSection "LSA Protection (RunAsPPL)"
$lsa = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -ErrorAction SilentlyContinue
if ($lsa) {
    Write-Host "RunAsPPL = $($lsa.RunAsPPL)  (0/absent = off, 1 = on, 2 = on with UEFI lock)"
} else {
    Write-Host "RunAsPPL not configured."
}

# ---------- 9. Group Policy ----------
Write-Section "9. Group Policy report"
try {
    Write-Host "Generating gpresult HTML report (this may take 30-60 seconds)..."
    & gpresult /h $gpoFile /f 2>&1 | Out-String
    if (Test-Path $gpoFile) {
        Write-Host "GPO report saved to: $gpoFile"
        Write-Host "Size: $((Get-Item $gpoFile).Length) bytes"
    } else {
        Write-Host "gpresult did not produce an output file."
    }
} catch {
    Write-Host "gpresult failed: $_"
}

# ---------- 10. Local firewall ----------
Write-Section "10. Local Windows Firewall state"
Write-Host "Note: this is the VM-side firewall, separate from any network firewall and proxy / SSL inspection."
Write-Host ""
try {
    Get-NetFirewallProfile -Profile Domain, Public, Private |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Format-Table -AutoSize
} catch {
    Write-Host "Get-NetFirewallProfile failed: $_"
}

# ---------- 11. Optional: outbound connectivity + SSL inspection check ----------
if ($TestConnectivity) {
    Write-Section "11. Outbound connectivity and SSL inspection check"
    Write-Host "Tests the standard set of Microsoft / Nerdio endpoints used by AVD"
    Write-Host "session hosts. For each: TCP, SSL handshake, and certificate issuer."
    Write-Host ""
    Write-Host "If the issuer field for a Microsoft endpoint shows anything other than"
    Write-Host "a Microsoft CA (e.g. Zscaler, Palo Alto, BlueCoat), SSL inspection is"
    Write-Host "intercepting the traffic. NME and AVD agents will fail."
    Write-Host ""

    $endpoints = @(
        [PSCustomObject]@{ URI = "login.microsoftonline.com";          Purpose = "Entra ID auth" }
        [PSCustomObject]@{ URI = "graph.microsoft.com";                Purpose = "Graph API" }
        [PSCustomObject]@{ URI = "management.azure.com";               Purpose = "Azure Resource Manager" }
        [PSCustomObject]@{ URI = "rdweb.wvd.microsoft.com";            Purpose = "AVD service plane" }
        [PSCustomObject]@{ URI = "nmwextensions.blob.core.windows.net"; Purpose = "NME extensions blob" }
        [PSCustomObject]@{ URI = "nwp-web-app.azurewebsites.net";      Purpose = "Nerdio licensing" }
        [PSCustomObject]@{ URI = "windowsupdate.microsoft.com";        Purpose = "Windows Update" }
    )

    foreach ($ep in $endpoints) {
        Write-Host ("Testing {0,-50} ({1})" -f $ep.URI, $ep.Purpose)
        $tcp  = $null
        $issuer = $null
        $err = $null
        try {
            $tcp = Test-NetConnection -ComputerName $ep.URI -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
        } catch {
            $err = "TCP test failed: $($_.Exception.Message)"
        }

        if ($tcp) {
            # Raw TcpClient + SslStream instead of Invoke-WebRequest / ServicePointManager:
            # ServicePointManager is only populated by the legacy HttpWebRequest stack, which
            # Invoke-WebRequest no longer uses under PowerShell 7/Core (it uses HttpClient), so
            # the old approach silently returned a null issuer there. This works the same on
            # Windows PowerShell 5.1 and PowerShell 7+, and always accepts the presented cert
            # (via the validation callback below) so we capture the issuer even when it isn't
            # trusted - which is exactly the case we're trying to detect.
            $tcpClient = $null
            $sslStream = $null
            try {
                $tcpClient = [System.Net.Sockets.TcpClient]::new()
                $connectTask = $tcpClient.ConnectAsync($ep.URI, 443)
                if (-not $connectTask.Wait(10000)) {
                    throw "connection timed out after 10s"
                }
                $sslStream = [System.Net.Security.SslStream]::new(
                    $tcpClient.GetStream(),
                    $false,
                    [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
                )
                $sslStream.AuthenticateAsClient($ep.URI)
                if ($sslStream.RemoteCertificate) {
                    $issuer = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate).Issuer
                }
            } catch {
                $err = "SSL handshake failed: $($_.Exception.Message)"
            } finally {
                if ($sslStream) { $sslStream.Dispose() }
                if ($tcpClient) { $tcpClient.Dispose() }
            }
        }

        $result = [PSCustomObject]@{
            URI = $ep.URI
            Purpose = $ep.Purpose
            TCP = if ($tcp) { 'OK' } else { 'FAIL' }
            CertIssuer = $issuer
            Error = $err
        }
        $result | Format-List
    }
}

# ---------- 12. Action items for the EDR admin ----------
Write-Section "12. EDR policy review - questions for the EDR admin"
Write-Host @"
The PowerShell tests above cannot read EDR policy from third-party consoles
(SentinelOne, CrowdStrike, etc.). Please share the following with whoever
administers the EDR product on the AVD VM:

  Nerdio runs PowerShell automation on AVD session hosts via Azure's Custom
  Script Extension. The script payload runs from these paths and may be
  obfuscated for IP protection:

    C:\Packages\Plugins\Microsoft.Compute.CustomScriptExtension\*\Downloads\*
    C:\Packages\Plugins\Microsoft.Powershell.DSC\*\*
    C:\Windows\Temp\NMWLogs\*
    C:\Windows\Temp\AppManagement\*

  Please review whether any of the following EDR policy elements could block
  execution from these paths on the AVD host policy:

    - Behavioural / Static AI engines
    - Application Control (if licensed)
    - Anti-tampering / lateral movement detection
    - Script execution restrictions

  If yes, please add path-based exclusions for the four paths above on the
  policy applied to AVD session hosts.
"@

# ---------- Wrap up ----------
Write-Section "Diagnostic complete"
Write-Host "Output directory: $workDir"
Stop-Transcript | Out-Null

# Zip everything
try {
    if (Test-Path $zipFile) { Remove-Item $zipFile -Force }
    Compress-Archive -Path "$workDir\*" -DestinationPath $zipFile -Force
    Write-Host ""
    Write-Host "==========================================="
    Write-Host "ZIP file ready to send back:"
    Write-Host "  $zipFile"
    Write-Host "==========================================="
} catch {
    Write-Host "Compress-Archive failed: $_"
    Write-Host "Source files are still available in $workDir"
}
