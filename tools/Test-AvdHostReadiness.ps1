<#
.SYNOPSIS
    Tests an AVD session host VM for OS-level policies and outbound network
    restrictions that may block Nerdio Manager for Enterprise (NME) automation.

.DESCRIPTION
    Captures the OS-level policy and security state of an AVD-candidate VM
    so we can identify potential blockers before NME provisions session hosts.
    Outputs a single ZIP file containing:
      - A transcript with all check results, ending in a PASS / WARN / FAIL summary
      - A Group Policy HTML report
      - AppLocker XML if applicable
      - With -TestConnectivity: connectivity_results.csv (one row per endpoint)
        and wvdagenturltool_output.txt (full output of Microsoft's tool, if found)

    Run as Administrator on a VM that is in scope of the same Intune device
    group, GPO, and EDR policy as future NME-managed AVD hosts.

    Checks performed (all read-only):
      - Execution policy, PowerShell language mode, WDAC, AppLocker, ASR, EDR
      - WinRM (service, Test-WSMan against localhost, WinRM policy settings).
        The Nerdio KB requires WinRM not to be disabled on session hosts.
      - Proxy configuration (WinHTTP, SYSTEM / machine / user WinINET, environment)
      - TLS 1.2 / Schannel settings, Windows activation, time source
      - With -TestConnectivity: outbound connectivity, see below.

    Connectivity (-TestConnectivity). Endpoints are organised in groups and
    aligned with the Nerdio KB article "Required outbound internet access from
    AVD session host VMs" and Microsoft's "Required FQDNs and endpoints for
    Azure Virtual Desktop":
      1. Nerdio (always tested): nmwextensions.blob.core.windows.net,
         catalogartifact.azureedge.net.
      2. Not covered by the Microsoft tool (always tested): Windows activation
         (azkms / kms.core.windows.net, TCP 1688, TCP test only).
      3. SSL inspection check (always tested, 443): the TLS certificate issuer
         is captured on a few key Microsoft endpoints even when Microsoft's tool
         runs, because that tool does not report SSL inspection.
      4. Standard AVD endpoints (fallback): tested only when Microsoft's
         WVDAgentUrlTool.exe is not found, or when its output does not mention
         that endpoint.
      5. Image build (only needed if building images with Nerdio scripted
         actions). Failures here are warnings only. Skip with
         -SkipImageBuildEndpoints.
      6. Customer storage (only if -FslogixStorageFqdn / -CssaStorageFqdn given).
    Microsoft's Azure Virtual Desktop Agent URL Tool (WVDAgentUrlTool.exe, part
    of the AVD agent under C:\Program Files\Microsoft RDInfra\RDAgent_*\) is run
    with a timeout and no console input; its output is kept in full and
    summarised.

    A non-Microsoft / non-public issuer (for example Zscaler or another proxy
    CA) on a Microsoft endpoint indicates SSL inspection, which can break NME
    and the AVD agents.

    Not tested, on purpose: management.azure.com, graph.microsoft.com and
    nwp-web-app.azurewebsites.net. They are used by the NME App Service, not by
    session hosts, so a network team does not need to open them for the VMs.
    Wildcard entries (*.wvd.microsoft.com, *.prod.warm.ingest.monitor.core.
    windows.net and similar) cannot be tested as such; one representative host
    is used where one is known.

    Note: this script tests the SESSION HOST side. It is different from
    Test-NmeDeploymentReadiness.ps1 (Get-Nerdio/NME-SE repo, which tests Azure
    subscription readiness pre-deployment) and NmeNetworkTest.ps1 (which runs
    in the NME App Service Kudu console).

    This is a standalone manual diagnostic - NOT an NME Scripted Action. It has
    no NME #variables block and is meant to be run directly on a candidate VM,
    often before that VM is even under NME management, so its output can be
    handed to a customer's EDR/network admin as a portable artifact.

.PARAMETER TestConnectivity
    If specified, also runs the outbound connectivity checks described above
    (Microsoft URL tool, per-endpoint DNS / TCP / TLS issuer, clock check).
    Skip this on environments where outbound is not yet open - it will simply
    return failures and add no signal.

.PARAMETER OutputPath
    The base directory where the output folder and ZIP file will be written.
    Defaults to C:\Temp. Use this on hardened VMs where C:\Temp is restricted.

.PARAMETER FslogixStorageFqdn
    Optional. FQDN of the customer's FSLogix storage account / file server,
    for example mystorage.file.core.windows.net. Tested on TCP 445 (SMB).
    Only used together with -TestConnectivity.

.PARAMETER CssaStorageFqdn
    Optional. FQDN of the NME "cssa" storage account if its name is known, for
    example cssaabc123.blob.core.windows.net. Tested on TCP 443 with the
    certificate issuer check. Only used together with -TestConnectivity.

.PARAMETER SkipImageBuildEndpoints
    Skips the optional "Image build" group (github.com and similar).

.EXAMPLE
    .\Test-AvdHostReadiness.ps1
    Runs the policy diagnostic only (including WinRM and proxy checks), outputs to C:\Temp.

.EXAMPLE
    .\Test-AvdHostReadiness.ps1 -TestConnectivity
    Runs the policy diagnostic plus Microsoft's URL tool, the Nerdio / KMS
    endpoint tests and the SSL inspection check.

.EXAMPLE
    .\Test-AvdHostReadiness.ps1 -TestConnectivity -FslogixStorageFqdn mystorage.file.core.windows.net -CssaStorageFqdn cssaabc123.blob.core.windows.net
    As above, and also tests SMB (445) to the FSLogix storage and HTTPS to the NME cssa storage account.

.EXAMPLE
    .\Test-AvdHostReadiness.ps1 -TestConnectivity -SkipImageBuildEndpoints -OutputPath "$env:USERPROFILE\Desktop"
    Skips the optional image build endpoints and writes output to the current user's Desktop.

.NOTES
    Requires PowerShell 5.1+ (Windows PowerShell 5.1 or PowerShell 7) and local Administrator rights.
    The script reads state only and does not modify the VM. Every network test
    and external tool call has a timeout.

    If the script cannot run at all:
      - "File ... cannot be loaded. The file is not digitally signed" means the
        effective execution policy is AllSigned (or RemoteSigned on a downloaded
        file). That is itself a finding: NME scripted actions will hit the same
        wall. Run it from a signed copy, or note the finding and move on.
      - Under Constrained Language Mode (WDAC / AppLocker script enforcement) the
        script still runs, reports the language mode as a FAIL, and skips the
        checks that need .NET (certificate issuer capture), saying so clearly.
    The execution policy check ignores a Process-scope override (for example
    "powershell -ExecutionPolicy Bypass"), because that would hide the real setting.
#>

[CmdletBinding()]
param(
    [switch]$TestConnectivity,
    [string]$OutputPath = "C:\Temp",
    [string]$FslogixStorageFqdn,
    [string]$CssaStorageFqdn,
    [switch]$SkipImageBuildEndpoints
)

$ErrorActionPreference = 'Continue'

# Constrained Language Mode blocks .NET method calls and ::new(). Detect it once
# and guard everything that needs .NET so the script reports rather than fails silently.
$script:FullLang = ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')

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

# [PSCustomObject]@{} is blocked in Constrained Language Mode on Windows PowerShell 5.1, so every
# object in this script is built through this helper (New-Object PSObject is allowed).
function New-Obj {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Property)
    New-Object -TypeName PSObject -Property $Property
}

# ---------- Result collection (feeds the final summary) ----------
$script:Results = @()
function Add-Result {
    param([string]$Area, [string]$Check, [ValidateSet('PASS','WARN','FAIL')][string]$Status, [string]$Detail)
    $script:Results += New-Obj ([ordered]@{ Area = $Area; Check = $Check; Status = $Status; Detail = $Detail })
}

# ---------- Helpers ----------
function Get-RootMessage {
    param($Exception)
    $ex = $Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    return $ex.Message
}

# Runs an external program with a hard timeout, no console input (stdin is an
# empty file, so nothing can wait for a key press) and captured output.
function Invoke-ExternalTool {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 30,
        [string]$WorkingDirectory
    )
    $result = New-Obj ([ordered]@{ Started = $false; TimedOut = $false; ExitCode = $null; Output = ''; Error = '' })
    $id  = Get-Random
    $out = Join-Path $env:TEMP "avdhr_${id}_out.txt"
    $err = Join-Path $env:TEMP "avdhr_${id}_err.txt"
    $inp = Join-Path $env:TEMP "avdhr_${id}_in.txt"
    try {
        New-Item -Path $inp -ItemType File -Force -ErrorAction Stop | Out-Null
        $sp = @{
            FilePath               = $FilePath
            RedirectStandardOutput = $out
            RedirectStandardError  = $err
            RedirectStandardInput  = $inp
            NoNewWindow            = $true
            PassThru               = $true
            ErrorAction            = 'Stop'
        }
        if ($Arguments.Count -gt 0) { $sp.ArgumentList = $Arguments }
        if ($WorkingDirectory)      { $sp.WorkingDirectory = $WorkingDirectory }
        $proc = Start-Process @sp
        $result.Started = $true
        $null = $proc.Handle   # keeps the handle so ExitCode is readable afterwards
        Wait-Process -Id $proc.Id -Timeout $TimeoutSeconds -ErrorAction SilentlyContinue
        if (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue) {
            $result.TimedOut = $true
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue   # only the tool we started
        } else {
            $result.ExitCode = $proc.ExitCode
        }
    } catch {
        $result.Error = $_.Exception.Message
    }
    if (Test-Path $out) { $result.Output = (Get-Content -Path $out -Raw -ErrorAction SilentlyContinue) }
    if (Test-Path $err) { $e = Get-Content -Path $err -Raw -ErrorAction SilentlyContinue; if ($e) { $result.Error = ($result.Error + " " + $e).Trim() } }
    Remove-Item -Path $out, $err, $inp -Force -ErrorAction SilentlyContinue
    if ($null -eq $result.Output) { $result.Output = '' }
    return $result
}

# Prints the output of Invoke-ExternalTool, or a clear reason it produced none.
function Write-ToolResult {
    param($Tool, [string]$Name)
    if (-not $Tool.Started) { Write-Host "$Name could not be started: $($Tool.Error)"; return }
    if ($Tool.TimedOut)     { Write-Host "$Name did not finish in time and was stopped (timeout)." }
    if ($Tool.Output)       { Write-Host $Tool.Output.TrimEnd() }
    if ($Tool.Error -and -not $Tool.TimedOut) { Write-Host "($Name stderr: $($Tool.Error))" }
}

Start-Transcript -Path $logFile -Force | Out-Null

Write-Host "AVD Host Readiness Test (NME pre-flight)"
Write-Host "Run time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host "User: $env:USERDOMAIN\$env:USERNAME"
Write-Host "PowerShell: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
Write-Host "Output path: $OutputPath"
Write-Host "Connectivity test: $($TestConnectivity.IsPresent)"
Write-Host ""

if (-not $TestConnectivity -and ($FslogixStorageFqdn -or $CssaStorageFqdn)) {
    Write-Host "NOTE: -FslogixStorageFqdn / -CssaStorageFqdn are only used with -TestConnectivity. They will be ignored."
    Write-Host ""
}

# ---------- 0. Elevation check ----------
Write-Section "0. Elevation check"
$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    # Constrained Language Mode blocks the .NET call above. High mandatory level SID = elevated.
    $who = Invoke-ExternalTool -FilePath "whoami.exe" -Arguments @('/groups') -TimeoutSeconds 15
    $isAdmin = ($who.Output -match 'S-1-16-12288')
}
if ($isAdmin) {
    Write-Host "Running as Administrator: YES"
} else {
    Write-Host "Running as Administrator: NO"
    Write-Host "WARNING: some checks will return incomplete data without elevation. Re-run as admin for a full picture."
}
if (-not $script:FullLang) {
    Write-Host ""
    Write-Host "WARNING: this session is in $($ExecutionContext.SessionState.LanguageMode), not FullLanguage."
    Write-Host "The script still runs, but checks that need .NET (certificate issuer capture, proxy"
    Write-Host "registry decoding) are skipped or reduced and are reported as such. See section 5."
}

# ---------- 1. System context ----------
Write-Section "1. System context"
Write-SubSection "OS"
Get-CimInstance -ClassName Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime |
    Format-List

Write-SubSection "PowerShell version"
New-Obj ([ordered]@{
    PSVersion       = $PSVersionTable.PSVersion.ToString()
    PSEdition       = $PSVersionTable.PSEdition
    CLRVersion      = $PSVersionTable.CLRVersion
    BuildVersion    = $PSVersionTable.BuildVersion
}) | Format-List

Write-SubSection "Domain join state"
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
New-Obj ([ordered]@{
    Domain         = $cs.Domain
    PartOfDomain   = $cs.PartOfDomain
    DomainRole     = $cs.DomainRole
    Workgroup      = $cs.Workgroup
}) | Format-List

Write-SubSection "Azure AD join state (dsregcmd)"
$dsreg = Invoke-ExternalTool -FilePath "dsregcmd.exe" -Arguments @('/status') -TimeoutSeconds 60
Write-ToolResult -Tool $dsreg -Name "dsregcmd"

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
Write-Host "      With -TestConnectivity the clock is also compared with an HTTPS Date header."
$w32 = Invoke-ExternalTool -FilePath "w32tm.exe" -Arguments @('/query', '/status') -TimeoutSeconds 20
Write-ToolResult -Tool $w32 -Name "w32tm"
if ($w32.Output -match '(Local CMOS Clock|Free-running System Clock)') {
    Write-Host "WARNING: time source is '$($Matches[1])', not a synchronised source (domain controller, NTP or Hyper-V / Azure host time)."
    Add-Result -Area 'System' -Check 'Time source' -Status 'WARN' -Detail "Time source is '$($Matches[1])'. A drifting clock breaks TLS and Entra ID sign-in."
}

Write-SubSection "TLS 1.2 / Schannel and .NET crypto settings"
Write-Host "Registry only. A missing value means the operating system default applies."
$schBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
$tls12Blocked = $false
foreach ($proto in 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3') {
    foreach ($side in 'Client', 'Server') {
        $k = Join-Path $schBase "$proto\$side"
        $v = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($v) {
            Write-Host ("  {0} {1}: Enabled={2} DisabledByDefault={3}" -f $proto, $side, $v.Enabled, $v.DisabledByDefault)
            if ($proto -eq 'TLS 1.2' -and $side -eq 'Client' -and (($v.Enabled -eq 0) -or ($v.DisabledByDefault -eq 1))) { $tls12Blocked = $true }
        }
    }
}
foreach ($net in "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319") {
    $v = Get-ItemProperty -Path $net -ErrorAction SilentlyContinue
    if ($v) { Write-Host ("  {0}: SchUseStrongCrypto={1} SystemDefaultTlsVersions={2}" -f $net, $v.SchUseStrongCrypto, $v.SystemDefaultTlsVersions) }
}
if ($tls12Blocked) {
    Write-Host "WARNING: TLS 1.2 is disabled for the client role. Azure endpoints require TLS 1.2 or later."
    Add-Result -Area 'System' -Check 'TLS 1.2 (client)' -Status 'FAIL' -Detail 'TLS 1.2 client is disabled in the Schannel registry. Azure / AVD endpoints need TLS 1.2+.'
} else {
    Add-Result -Area 'System' -Check 'TLS 1.2 (client)' -Status 'PASS' -Detail 'Not disabled in the Schannel registry (OS default applies where not set).'
}

Write-SubSection "Windows activation"
Write-Host "Windows on Azure activates against azkms.core.windows.net / kms.core.windows.net on TCP 1688."
try {
    $lic = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop |
        Select-Object -First 1
    if ($lic) {
        $lic | Select-Object Name, LicenseStatus, KeyManagementServiceMachine, DiscoveredKeyManagementServiceMachineName | Format-List
        Write-Host "LicenseStatus key: 0=Unlicensed, 1=Licensed, 2=OOBGrace, 3=OOTGrace, 4=NonGenuineGrace, 5=Notification, 6=ExtendedGrace"
        if ($lic.LicenseStatus -eq 1) {
            Add-Result -Area 'System' -Check 'Windows activation' -Status 'PASS' -Detail 'Licensed.'
        } else {
            Add-Result -Area 'System' -Check 'Windows activation' -Status 'WARN' -Detail "LicenseStatus $($lic.LicenseStatus) (1 = licensed). Check TCP 1688 to azkms / kms.core.windows.net."
        }
    } else {
        Write-Host "No Windows licence product with a partial key found."
        Add-Result -Area 'System' -Check 'Windows activation' -Status 'WARN' -Detail 'No licence product with a partial product key found.'
    }
} catch {
    Write-Host "Licensing query failed: $($_.Exception.Message)"
    Add-Result -Area 'System' -Check 'Windows activation' -Status 'WARN' -Detail 'Licensing query failed, activation state unknown.'
}

# ---------- 2. EDR / SentinelOne ----------
Write-Section "2. EDR agents (SentinelOne, CrowdStrike, others)"
Write-Host "Note: third-party EDR policy is configured centrally in the EDR console."
Write-Host "This section confirms agent state on the VM only. Policy review must"
Write-Host "happen with the EDR admin, see the EDR questions section near the end."
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
    $sctlStatus = Invoke-ExternalTool -FilePath $sctl.FullName -Arguments @('status') -TimeoutSeconds 30
    Write-ToolResult -Tool $sctlStatus -Name "SentinelCtl status"
} else {
    Write-Host "SentinelCtl.exe not found - SentinelOne may not be installed."
}

Write-SubSection "Recent local SentinelOne threats (if SentinelCtl supports threat_list)"
if ($sctl) {
    $sctlThreats = Invoke-ExternalTool -FilePath $sctl.FullName -Arguments @('threat_list') -TimeoutSeconds 30
    if ($sctlThreats.Started) {
        ($sctlThreats.Output -split "\r?\n" | Select-Object -First 50) -join "`n"
        if ($sctlThreats.TimedOut) { Write-Host "(threat_list timed out and was stopped)" }
    } else {
        Write-Host "SentinelCtl threat_list could not be started: $($sctlThreats.Error)"
    }
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
$lockdown = $env:__PSLockdownPolicy
if ($lockdown) { Write-Host "__PSLockdownPolicy environment variable: $lockdown (system lockdown, forces Constrained Language Mode)" }
if ($lang -ne 'FullLanguage') {
    Write-Host ""
    Write-Host "WARNING: Language mode is NOT FullLanguage."
    Write-Host "NME scripted actions WILL fail with dot-sourcing errors."
    Write-Host "Reference: Nerdio community post on WDAC script enforcement."
    Add-Result -Area 'Policy' -Check 'PowerShell language mode' -Status 'FAIL' -Detail "$lang. NME scripted actions will fail."
} else {
    Write-Host "Note: this is the language mode of THIS session. Scripts run by the Custom Script Extension"
    Write-Host "run as SYSTEM and can be treated differently by WDAC, so confirm with the policy owner."
    Add-Result -Area 'Policy' -Check 'PowerShell language mode' -Status 'PASS' -Detail 'FullLanguage in this session.'
}

Write-SubSection "Active WDAC policies (CiTool)"
if (Get-Command CiTool.exe -ErrorAction SilentlyContinue) {
    $ci = Invoke-ExternalTool -FilePath "CiTool.exe" -Arguments @('--list-policies') -TimeoutSeconds 30
    Write-ToolResult -Tool $ci -Name "CiTool"
} else {
    Write-Host "CiTool not available on this OS."
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
$epList = Get-ExecutionPolicy -List
$epList | Format-Table -AutoSize

# Get-ExecutionPolicy (no -List) honours a Process-scope override such as
# "-ExecutionPolicy Bypass", which would hide the real machine setting. Work it out
# ourselves in precedence order, skipping Process.
$effective = 'Undefined'
foreach ($scope in 'MachinePolicy', 'UserPolicy', 'CurrentUser', 'LocalMachine') {
    $entry = $epList | Where-Object { "$($_.Scope)" -eq $scope } | Select-Object -First 1
    if ($entry -and "$($entry.ExecutionPolicy)" -ne 'Undefined') { $effective = "$($entry.ExecutionPolicy)"; $effectiveScope = $scope; break }
}
if ($effective -eq 'Undefined') { $effective = 'Restricted'; $effectiveScope = 'default (Windows client default)'; if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) { $effective = 'RemoteSigned'; $effectiveScope = 'default (Windows Server default)' } }
$processScope = $epList | Where-Object { "$($_.Scope)" -eq 'Process' } | Select-Object -First 1
Write-Host "Effective policy (ignoring Process scope): $effective  [from $effectiveScope]"
Write-Host "Reported by Get-ExecutionPolicy:            $(Get-ExecutionPolicy)"
$epStatus = 'PASS'
$epDetail = "$effective (from $effectiveScope)."
if ($effective -in 'AllSigned', 'Restricted') {
    Write-Host ""
    Write-Host "WARNING: Effective execution policy is $effective."
    Write-Host "Unsigned PowerShell will be blocked. NME scripted actions will fail unless"
    Write-Host "scripts are signed with a certificate trusted on this VM."
    $epStatus = 'FAIL'
    $epDetail = "$effective (from $effectiveScope). Unsigned scripts are blocked."
}
if ($processScope -and "$($processScope.ExecutionPolicy)" -ne 'Undefined') {
    Write-Host ""
    Write-Host "NOTE: a Process-scope policy ($($processScope.ExecutionPolicy)) is set for this session, so this script"
    Write-Host "      may have run despite the policy above. NME runs its scripts in its own sessions."
    if ($epStatus -eq 'PASS') { $epStatus = 'WARN' }
    $epDetail += " Process-scope override ($($processScope.ExecutionPolicy)) was in use for this run."
}
Add-Result -Area 'Policy' -Check 'Execution policy' -Status $epStatus -Detail $epDetail

# ---------- 7. AppLocker ----------
Write-Section "7. AppLocker"
try {
    $applocker = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
    if ($applocker) {
        Write-Host "Effective AppLocker rule collections in force:"
        $collections = @()
        foreach ($m in ([regex]::Matches([string]$applocker, '<RuleCollection\s+Type="(\w+)"\s+EnforcementMode="(\w+)"'))) {
            Write-Host ("  {0}: {1}" -f $m.Groups[1].Value, $m.Groups[2].Value)
            $collections += New-Obj ([ordered]@{ Type = $m.Groups[1].Value; Mode = $m.Groups[2].Value })
        }
        Write-Host ""
        Write-Host "Full AppLocker XML saved to: applocker_policy.xml"
        $applocker | Out-File -FilePath (Join-Path $workDir "applocker_policy.xml") -Encoding utf8
        $enforced = @($collections | Where-Object { $_.Mode -eq 'Enabled' })
        if ($enforced.Count -gt 0) {
            Add-Result -Area 'Policy' -Check 'AppLocker' -Status 'WARN' -Detail ("Enforced collections: " + (($enforced | ForEach-Object { $_.Type }) -join ', ') + ". Review the rules against the NME script paths.")
        } elseif ($collections.Count -gt 0) {
            Add-Result -Area 'Policy' -Check 'AppLocker' -Status 'PASS' -Detail 'Rule collections present but none enforced (audit only / not configured).'
        } else {
            Add-Result -Area 'Policy' -Check 'AppLocker' -Status 'PASS' -Detail 'No rule collections in the effective policy.'
        }
    } else {
        Write-Host "No effective AppLocker policy."
        Add-Result -Area 'Policy' -Check 'AppLocker' -Status 'PASS' -Detail 'No effective AppLocker policy.'
    }
} catch {
    Write-Host "AppLocker query failed: $_"
    Add-Result -Area 'Policy' -Check 'AppLocker' -Status 'WARN' -Detail 'AppLocker policy query failed, state unknown.'
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
Write-Host "Generating gpresult HTML report (this may take 30-60 seconds, 3 minute limit)..."
# gpresult rejects output paths longer than 127 characters, so write to a short temp path and copy.
$gpTemp = Join-Path $env:TEMP ("avdhr_gpo_{0}.html" -f (Get-Random))
$gp = Invoke-ExternalTool -FilePath "gpresult.exe" -Arguments @('/h', $gpTemp, '/f') -TimeoutSeconds 180
Write-ToolResult -Tool $gp -Name "gpresult"
if (Test-Path $gpTemp) {
    Copy-Item -Path $gpTemp -Destination $gpoFile -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $gpTemp -Force -ErrorAction SilentlyContinue
}
if (Test-Path $gpoFile) {
    Write-Host "GPO report saved to: $gpoFile"
    Write-Host "Size: $((Get-Item $gpoFile).Length) bytes"
} else {
    Write-Host "gpresult did not produce an output file."
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

# ---------- 11. WinRM ----------
Write-Section "11. WinRM"
Write-Host "The Nerdio KB says WinRM must not be disabled on session host VMs."
Write-Host ""
$winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($winrmSvc) {
    $winrmSvc | Format-Table Name, Status, StartType -AutoSize
} else {
    Write-Host "WinRM service not found."
}

Write-SubSection "Test-WSMan localhost (30 second limit)"
$wsmanOk = $false
$wsmanText = ''
try {
    $job = Start-Job -ScriptBlock {
        try { Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-String } catch { "ERROR: " + $_.Exception.Message }
    }
    if (Wait-Job -Job $job -Timeout 30) {
        $wsmanText = (Receive-Job -Job $job | Out-String).Trim()
        $wsmanOk = ($wsmanText -and $wsmanText -notmatch '^ERROR:')
    } else {
        $wsmanText = 'ERROR: Test-WSMan did not respond within 30 seconds.'
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
} catch {
    $wsmanText = "ERROR: could not start the Test-WSMan check: $($_.Exception.Message)"
}
Write-Host $wsmanText

Write-SubSection "WinRM policy settings (Group Policy)"
$winrmPolicyIssue = $false
foreach ($key in "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client") {
    $v = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($v) {
        Write-Host "$key"
        $v | Select-Object * -ExcludeProperty PS* | Format-List
        if ($v.PSObject.Properties.Name -contains 'AllowAutoConfig' -and $v.AllowAutoConfig -eq 0) { $winrmPolicyIssue = $true }
    } else {
        Write-Host "$key : no policy set"
    }
}
if ($winrmPolicyIssue) { Write-Host "WARNING: policy 'Allow remote server management through WinRM' is set to Disabled." }

$winrmStatus = 'PASS'
$winrmDetail = ''
if (-not $winrmSvc) {
    $winrmStatus = 'FAIL'; $winrmDetail = 'WinRM service not found.'
} elseif ("$($winrmSvc.StartType)" -eq 'Disabled') {
    $winrmStatus = 'FAIL'; $winrmDetail = 'WinRM service start type is Disabled.'
} elseif ($winrmPolicyIssue) {
    $winrmStatus = 'WARN'; $winrmDetail = "Service $($winrmSvc.Status) / $($winrmSvc.StartType), but a policy disables WinRM remote management."
} elseif ($winrmSvc.Status -ne 'Running') {
    $winrmStatus = 'WARN'; $winrmDetail = "Service is $($winrmSvc.Status) (start type $($winrmSvc.StartType)). Not disabled, but not running now."
} elseif (-not $wsmanOk) {
    $winrmStatus = 'WARN'; $winrmDetail = "Service running ($($winrmSvc.StartType)) but Test-WSMan localhost failed or timed out."
} else {
    $winrmDetail = "Service running ($($winrmSvc.StartType)), Test-WSMan localhost succeeded."
}
Add-Result -Area 'Policy' -Check 'WinRM' -Status $winrmStatus -Detail $winrmDetail

# ---------- 12. Proxy settings ----------
Write-Section "12. Proxy settings"
Write-Host "The AVD agents run as SYSTEM / Network Service and use the machine-wide (WinHTTP) proxy or"
Write-Host "the SYSTEM account's WinINET settings, not the signed-in user's. Microsoft recommends bypassing"
Write-Host "proxies for AVD traffic and does not support proxies that require authentication."
Write-Host "A direct TCP test below can FAIL even though traffic is allowed through a proxy."
Write-Host ""

function ConvertTo-ProxyHostPort {
    param([string]$Value)
    if (-not $Value) { return $null }
    $pick = $null
    $entries = $Value -split ';'
    foreach ($e in $entries) { if ($e -match '^https=(.+)$') { $pick = $Matches[1]; break } }
    if (-not $pick) { foreach ($e in $entries) { if ($e -match '^http=(.+)$') { $pick = $Matches[1]; break } } }
    if (-not $pick) { foreach ($e in $entries) { if ($e -and $e -notmatch '=') { $pick = $e; break } } }
    if (-not $pick) { return $null }
    $pick = ($pick -replace '^[a-z]+://', '').TrimEnd('/')
    if ($pick -match '^([^:]+):(\d+)$') { return New-Obj ([ordered]@{ Host = $Matches[1]; Port = [int]$Matches[2] }) }
    return $null
}

Write-SubSection "netsh winhttp show proxy (machine-wide WinHTTP)"
$netsh = Invoke-ExternalTool -FilePath "netsh.exe" -Arguments @('winhttp', 'show', 'proxy') -TimeoutSeconds 15
Write-ToolResult -Tool $netsh -Name "netsh winhttp"

$proxyFindings = @()      # human-readable list of what is configured
$staticProxyString = ''   # first static proxy found, in WinHTTP / WinINET syntax
$pacOrAuto = $false

# WinHTTP: decode the registry blob (language independent). Fall back to netsh text.
$winhttpDecoded = $false
if ($script:FullLang) {
    try {
        $blob = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name WinHttpSettings -ErrorAction Stop).WinHttpSettings
        if ($blob -and $blob.Length -ge 16) {
            $flags = [int]$blob[8]
            $off = 12
            $pLen = [BitConverter]::ToInt32($blob, $off); $off += 4
            $proxyStr = ''
            if ($pLen -gt 0 -and ($off + $pLen) -le $blob.Length) { $proxyStr = [Text.Encoding]::ASCII.GetString($blob, $off, $pLen); $off += $pLen }
            if (($flags -band 2) -and $proxyStr) { $proxyFindings += "WinHTTP proxy server: $proxyStr"; if (-not $staticProxyString) { $staticProxyString = $proxyStr } }
            if ($flags -band 4) { $proxyFindings += 'WinHTTP uses an automatic configuration script (PAC)'; $pacOrAuto = $true }
            if ($flags -band 8) { $proxyFindings += 'WinHTTP uses automatic proxy detection (WPAD)'; $pacOrAuto = $true }
            $winhttpDecoded = $true
        } else {
            $winhttpDecoded = $true   # no blob = direct access
        }
    } catch { $winhttpDecoded = $true }
}
if (-not $winhttpDecoded) {
    if ($netsh.Output -match 'Proxy Server\(s\)\s*:\s*(\S+)') { $proxyFindings += "WinHTTP proxy server: $($Matches[1])"; $staticProxyString = $Matches[1] }
    elseif ($netsh.Output -and $netsh.Output -notmatch 'Direct access') { $proxyFindings += 'WinHTTP output not recognised (non-English OS or unexpected format). Read the netsh output above.' }
}

Write-SubSection "WinINET proxy settings (SYSTEM profile, machine policy, current user)"
$inetKeys = @(
    @{ Name = 'SYSTEM profile (HKU\.DEFAULT)'; Path = 'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Relevant = $true }
    @{ Name = 'Machine policy (HKLM)';         Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'; Relevant = $true }
    @{ Name = 'Machine (HKLM)';                Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'; Relevant = $true }
    @{ Name = "Current user ($env:USERNAME)";   Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; Relevant = $false }
)
foreach ($k in $inetKeys) {
    $v = Get-ItemProperty -Path $k.Path -ErrorAction SilentlyContinue
    $enabled = if ($v) { $v.ProxyEnable } else { $null }
    $server  = if ($v) { $v.ProxyServer } else { $null }
    $pac     = if ($v) { $v.AutoConfigURL } else { $null }
    $detect  = if ($v) { $v.AutoDetect } else { $null }
    Write-Host ("  {0}: ProxyEnable={1} ProxyServer={2} AutoConfigURL={3} AutoDetect={4}" -f $k.Name, $enabled, $server, $pac, $detect)
    if ($enabled -eq 1 -and $server) {
        $proxyFindings += "WinINET $($k.Name): proxy $server" + $(if (-not $k.Relevant) { ' (this user only, agents do not use it)' } else { '' })
        if ($k.Relevant -and -not $staticProxyString) { $staticProxyString = [string]$server }
    }
    if ($pac) {
        $proxyFindings += "WinINET $($k.Name): PAC script $pac" + $(if (-not $k.Relevant) { ' (this user only, agents do not use it)' } else { '' })
        if ($k.Relevant) { $pacOrAuto = $true }
    }
}

Write-SubSection "Per-service proxy for SYSTEM (bitsadmin /util /getieproxy)"
$bits = Invoke-ExternalTool -FilePath "bitsadmin.exe" -Arguments @('/util', '/getieproxy', 'LOCALSYSTEM') -TimeoutSeconds 20
Write-ToolResult -Tool $bits -Name "bitsadmin"
if ($bits.Output -match 'ProxyList\s*=\s*(\S+)' -and $Matches[1] -notmatch '^(NULL|\(null\))$') {
    $proxyFindings += "SYSTEM proxy (bitsadmin): $($Matches[1])"
    if (-not $staticProxyString) { $staticProxyString = $Matches[1] }
}
if ($bits.Output -match 'AutoConfigURL\s*=\s*(\S+)' -and $Matches[1] -notmatch '^(NULL|\(null\))$') {
    $proxyFindings += "SYSTEM PAC script (bitsadmin): $($Matches[1])"; $pacOrAuto = $true
}

Write-SubSection "Environment variables"
$envProxy = @()
foreach ($n in 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY') {
    $val = (Get-Item -Path "Env:$n" -ErrorAction SilentlyContinue).Value
    if ($val) { $envProxy += "$n=$val" }
}
if ($envProxy.Count -gt 0) { $envProxy | ForEach-Object { Write-Host "  $_" }; $proxyFindings += "Environment: $($envProxy -join ', ')" } else { Write-Host "  None set" }

$script:ProxyStatic = ConvertTo-ProxyHostPort -Value $staticProxyString
$script:ProxyConfigured = ($proxyFindings.Count -gt 0)
$script:ProxyPac = $pacOrAuto

Write-Host ""
if ($script:ProxyConfigured) {
    Write-Host "WARNING: a proxy is configured on this VM:"
    $proxyFindings | ForEach-Object { Write-Host "  - $_" }
    Write-Host "A direct TCP test to an endpoint can FAIL when traffic is only allowed through the proxy, and a"
    Write-Host "direct test can PASS while the agents' real path (via the proxy) is blocked or SSL-inspected."
    Write-Host "Read the connectivity results below with that in mind."
    Add-Result -Area 'Network' -Check 'Proxy' -Status 'WARN' -Detail ("Proxy configured: " + ($proxyFindings -join '; '))
} else {
    Write-Host "No machine-wide proxy detected (direct access)."
    Add-Result -Area 'Network' -Check 'Proxy' -Status 'PASS' -Detail 'No proxy configured; direct access.'
}

# ---------- 13. Optional: outbound connectivity + SSL inspection check ----------
$connectivityRows = @()
if ($TestConnectivity) {
    Write-Section "13. Outbound connectivity and SSL inspection check"
    Write-Host "Every network test has a timeout (10 seconds per connection / handshake)."
    Write-Host "Wildcard entries cannot be tested as such; a representative host is used where one is known."
    Write-Host ""

    # --- helpers ---------------------------------------------------------------
    function Test-TcpConnect {
        param([string]$HostName, [int]$Port, [int]$TimeoutMs = 10000)
        $r = New-Obj ([ordered]@{ Ok = $false; NotTested = $false; Error = $null })
        if ($script:FullLang) {
            $c = $null
            try {
                $c = [System.Net.Sockets.TcpClient]::new()
                $t = $c.ConnectAsync($HostName, $Port)
                if ($t.Wait($TimeoutMs)) { $r.Ok = $c.Connected; if (-not $r.Ok) { $r.Error = 'not connected' } }
                else { $r.Error = "timed out after $($TimeoutMs / 1000) seconds" }
            } catch {
                $r.Error = Get-RootMessage $_.Exception
            } finally {
                if ($c) { $c.Dispose() }
            }
        } else {
            # No .NET: use Test-NetConnection in a job so it can be timed out. If a job cannot be started,
            # call it directly (bounded by the OS TCP timeout, about 20 seconds). If that fails too, the
            # result is "not tested" - never a network FAIL caused by the script's own limitation.
            try {
                $job = Start-Job -ScriptBlock { param($h, $p) Test-NetConnection -ComputerName $h -Port $p -WarningAction SilentlyContinue -InformationLevel Quiet } -ArgumentList $HostName, $Port -ErrorAction Stop
                if (Wait-Job -Job $job -Timeout 25) { $r.Ok = [bool](Receive-Job -Job $job); if (-not $r.Ok) { $r.Error = 'connection failed' } }
                else { $r.Error = 'timed out after 25 seconds' }
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            } catch {
                try {
                    $r.Ok = [bool](Test-NetConnection -ComputerName $HostName -Port $Port -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction Stop)
                    if (-not $r.Ok) { $r.Error = 'connection failed' }
                } catch {
                    $r.NotTested = $true
                    $r.Error = "could not be tested in this session: $($_.Exception.Message)"
                }
            }
        }
        return $r
    }

    # TcpClient + SslStream instead of Invoke-WebRequest / ServicePointManager: it behaves the same on
    # Windows PowerShell 5.1 and PowerShell 7, and the validation callback always accepts the presented
    # certificate, so the issuer is captured even when the certificate is NOT trusted - which is exactly
    # the case being detected. With -ProxyHost, an HTTP CONNECT tunnel is opened first (no authentication).
    function Get-TlsCertificateInfo {
        param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 10000, [string]$ProxyHost, [int]$ProxyPort)
        $r = New-Obj ([ordered]@{ Ok = $false; Issuer = $null; Subject = $null; Protocol = $null; ChainTrusted = $null; ChainRoot = $null; Error = $null })
        if (-not $script:FullLang) { $r.Error = 'skipped: Constrained Language Mode blocks the .NET calls needed'; return $r }
        $tcp = $null; $ssl = $null
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $target = $HostName; $targetPort = $Port
            if ($ProxyHost) { $target = $ProxyHost; $targetPort = $ProxyPort }
            $conn = $tcp.ConnectAsync($target, $targetPort)
            if (-not $conn.Wait($TimeoutMs)) { throw "connection to $target`:$targetPort timed out after $($TimeoutMs / 1000) seconds" }
            $ns = $tcp.GetStream()
            $ns.ReadTimeout = $TimeoutMs; $ns.WriteTimeout = $TimeoutMs
            if ($ProxyHost) {
                $req = [Text.Encoding]::ASCII.GetBytes(("CONNECT {0}:{1} HTTP/1.1`r`nHost: {0}:{1}`r`n`r`n" -f $HostName, $Port))
                $ns.Write($req, 0, $req.Length)
                $buf = [byte[]]::new(4096)
                $n = $ns.Read($buf, 0, $buf.Length)
                $first = ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -split "\r?\n")[0]
                if ($first -notmatch '^HTTP/\d\.\d 200') { throw "proxy did not open the tunnel: $first" }
            }
            $ssl = [System.Net.Security.SslStream]::new($ns, $false, [System.Net.Security.RemoteCertificateValidationCallback]{ $true })
            $protocols = [System.Security.Authentication.SslProtocols]::Tls12
            if ([enum]::GetNames([System.Security.Authentication.SslProtocols]) -contains 'Tls13') { $protocols = [System.Security.Authentication.SslProtocols]'Tls12, Tls13' }
            $ssl.AuthenticateAsClient($HostName, $null, $protocols, $false)
            $r.Protocol = "$($ssl.SslProtocol)"
            if ($ssl.RemoteCertificate) {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
                $r.Issuer = $cert.Issuer
                $r.Subject = $cert.Subject
                try {
                    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(5)
                    $r.ChainTrusted = $chain.Build($cert)
                    if ($chain.ChainElements.Count -gt 0) { $r.ChainRoot = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject }
                } catch { $r.ChainTrusted = $null }
            }
            $r.Ok = $true
        } catch {
            $r.Error = "TLS handshake failed: $(Get-RootMessage $_.Exception)"
        } finally {
            if ($ssl) { $ssl.Dispose() }
            if ($tcp) { $tcp.Dispose() }
        }
        return $r
    }

    function Resolve-HostQuiet {
        param([string]$HostName)
        $r = New-Obj ([ordered]@{ Ok = $true; Addresses = ''; Error = $null })
        if ($HostName -match '^\d{1,3}(\.\d{1,3}){3}$') { $r.Addresses = $HostName; return $r }
        if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) { $r.Addresses = 'n/a'; return $r }
        try {
            $a = Resolve-DnsName -Name $HostName -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress }
            if ($a) { $r.Addresses = (@($a) -join ',') } else { $r.Ok = $false; $r.Error = 'no address returned' }
        } catch { $r.Ok = $false; $r.Error = $_.Exception.Message }
        return $r
    }

    function New-Endpoint {
        param([string]$Group, [string]$HostName, [int]$Port, [bool]$Tls, [string]$Mode, [string]$Requirement, [string]$Purpose, [string]$IssuerSet = 'Microsoft', [bool]$SslCheck = $false)
        New-Obj ([ordered]@{ Group = $Group; Endpoint = $HostName; Port = $Port; Tls = $Tls; Mode = $Mode; Requirement = $Requirement; Purpose = $Purpose; IssuerSet = $IssuerSet; SslCheck = $SslCheck; Source = 'Script' })
    }

    # Issuers expected on Microsoft endpoints, and a wider set of public CAs for third-party download sites.
    $issuerMicrosoft = 'Microsoft|DigiCert|Baltimore CyberTrust|GlobalSign'
    $issuerPublic    = 'Microsoft|DigiCert|Baltimore CyberTrust|GlobalSign|Sectigo|USERTrust|Amazon|Starfield|Entrust|Let''s Encrypt|ISRG|Google Trust|GTS CA|Cloudflare|Go Daddy'

    $gNerdio  = 'Nerdio (always tested)'
    $gNoMs    = 'Not covered by the Microsoft tool (always tested)'
    $gSsl     = 'SSL inspection check (always tested)'
    $gStd     = 'Standard AVD endpoints (fallback)'
    $gImage   = 'Image build (only needed if building images with Nerdio scripted actions)'
    $gStorage = 'Customer storage'

    # --- 13a. Microsoft's Azure Virtual Desktop Agent URL Tool -------------------
    Write-SubSection "13a. Microsoft Azure Virtual Desktop Agent URL Tool (WVDAgentUrlTool.exe)"
    Write-Host "Documented requirements: RDAgent 1.0.2944.400 or later, .NET Framework 4.6.2, and"
    Write-Host "WVDAgentUrlTool.config in the same folder as the .exe. It does not verify wildcard entries,"
    Write-Host "only the specific hosts behind them, and it does not report SSL inspection."
    $toolText = ''
    $toolUsable = $false
    $programFiles = $env:ProgramW6432; if (-not $programFiles) { $programFiles = $env:ProgramFiles }
    $rdRoot = Join-Path $programFiles 'Microsoft RDInfra'
    $agentDirs = @()
    if (Test-Path $rdRoot) {
        $agentDirs = @(Get-ChildItem -Path $rdRoot -Directory -Filter 'RDAgent_*' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^RDAgent_(\d+(\.\d+)+)$' } |
            Sort-Object -Property @{ Expression = { ($_.Name -replace '^RDAgent_', '' -split '\.' | ForEach-Object { '{0:D8}' -f [int]$_ }) -join '.' }; Descending = $true })
    }
    $toolExe = $null
    foreach ($d in $agentDirs) {
        $cand = Join-Path $d.FullName 'WVDAgentUrlTool.exe'
        if (Test-Path $cand) { $toolExe = $cand; break }
    }
    if ($agentDirs.Count -gt 0) { Write-Host ("Agent folders found: " + (($agentDirs | ForEach-Object { $_.Name }) -join ', ')) }

    if ($toolExe) {
        $toolDir = Split-Path $toolExe -Parent
        Write-Host "Using (highest agent version with the tool): $toolExe"
        if (-not (Test-Path (Join-Path $toolDir 'WVDAgentUrlTool.config'))) {
            Write-Host "Note: WVDAgentUrlTool.config is not in $toolDir (older tool versions need it there)."
        }
        Write-Host "Running with a 120 second limit and no console input..."
        Write-Host ""
        $tool = Invoke-ExternalTool -FilePath $toolExe -WorkingDirectory $toolDir -TimeoutSeconds 120
        $toolText = ($tool.Output + "`n" + $tool.Error).Trim()
        Write-Host "----- WVDAgentUrlTool.exe output (begin) -----"
        if ($toolText) { Write-Host $toolText } else { Write-Host "(no output)" }
        Write-Host "----- WVDAgentUrlTool.exe output (end) -----"
        Write-Host ("Exit code: {0}   Timed out: {1}" -f $tool.ExitCode, $tool.TimedOut)
        $toolText | Out-File -FilePath (Join-Path $workDir 'wvdagenturltool_output.txt') -Encoding utf8

        # The output format is not documented, so classify by keywords and keep the raw file as the source of truth.
        $accessible = @(); $inaccessible = @(); $mode = $null
        foreach ($line in ($toolText -split "\r?\n")) {
            $l = $line.Trim()
            if (-not $l) { continue }
            $hasHost = $l -match '([a-z0-9*][a-z0-9.\-*]*\.[a-z]{2,}|\b\d{1,3}(\.\d{1,3}){3}\b)'
            $neg = $l -match 'not accessible|inaccessible|not reachable|unreachable|cannot (be )?(reach|access)|unable to|failed|blocked|denied|timed out|error'
            $pos = $l -match '\baccessible\b|\breachable\b|success|\bpassed\b|\bOK\b'
            if ($neg)      { if ($hasHost) { $inaccessible += $l } else { $mode = 'neg' }; continue }
            if ($pos)      { if ($hasHost) { $accessible += $l }   else { $mode = 'pos' }; continue }
            if ($hasHost)  { if ($mode -eq 'neg') { $inaccessible += $l } elseif ($mode -eq 'pos') { $accessible += $l } }
        }
        Write-Host ""
        Write-Host ("Summary: {0} accessible line(s), {1} NOT accessible line(s) (keyword based; see wvdagenturltool_output.txt)." -f $accessible.Count, $inaccessible.Count)
        if ($inaccessible.Count -gt 0) { Write-Host "NOT accessible:"; $inaccessible | ForEach-Object { Write-Host "  $_" } }
        if ($accessible.Count -gt 0)   { Write-Host "Accessible:";     $accessible   | ForEach-Object { Write-Host "  $_" } }

        if ($tool.TimedOut) {
            Add-Result -Area 'Connectivity' -Check 'Microsoft URL tool' -Status 'WARN' -Detail 'WVDAgentUrlTool.exe did not finish within 120 seconds and was stopped. Result inconclusive.'
        } elseif (-not $tool.Started) {
            Add-Result -Area 'Connectivity' -Check 'Microsoft URL tool' -Status 'WARN' -Detail "WVDAgentUrlTool.exe could not be started: $($tool.Error). Fell back to the script's own list."
        } elseif ($inaccessible.Count -gt 0) {
            Add-Result -Area 'Connectivity' -Check 'Microsoft URL tool' -Status 'FAIL' -Detail ("{0} URL line(s) not accessible, {1} accessible. See wvdagenturltool_output.txt." -f $inaccessible.Count, $accessible.Count)
            $toolUsable = $true
        } elseif ($accessible.Count -gt 0) {
            Add-Result -Area 'Connectivity' -Check 'Microsoft URL tool' -Status 'PASS' -Detail ("{0} URL line(s) accessible, none reported as not accessible." -f $accessible.Count)
            $toolUsable = $true
        } else {
            $reason = 'its output could not be classified'
            if ($toolText -match '(?m)^.*failed with:?\s*(.+)$') { $reason = "the tool reported: $($Matches[1].Trim())" }
            $hint = ''
            if ($toolText -match 'named pipe' -or -not $isAdmin) { $hint = ' It talks to the RDAgent service, so run it elevated with the agent service running.' }
            Write-Host "The tool gave no usable result ($reason). The script's own endpoint list is used instead.$hint"
            Add-Result -Area 'Connectivity' -Check 'Microsoft URL tool' -Status 'WARN' -Detail "No usable result: $reason.$hint Script used its own endpoint list. See wvdagenturltool_output.txt."
        }
    } else {
        Write-Host ""
        if (Test-Path $rdRoot) {
            Write-Host "WVDAgentUrlTool.exe was NOT found under $rdRoot\RDAgent_*\ (agent folders: $($agentDirs.Count))."
        } else {
            Write-Host "The AVD agent is not installed ($rdRoot does not exist), so Microsoft's URL tool is not available."
        }
        Write-Host "Falling back to the script's own standard AVD endpoint list (group: $gStd)."
        Add-Result -Area 'Connectivity' -Check 'Microsoft URL tool' -Status 'WARN' -Detail 'WVDAgentUrlTool.exe not found (AVD agent not installed or too old). Script used its own standard AVD endpoint list instead.'
    }

    # --- 13b. Clock check -------------------------------------------------------
    Write-SubSection "13b. Clock check (HTTPS Date header from www.microsoft.com)"
    try {
        $resp = Invoke-WebRequest -Uri 'https://www.microsoft.com' -Method Head -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $dateHeader = @($resp.Headers['Date'])[0]
        $remote = [datetime]$dateHeader
        $skew = [math]::Abs(((Get-Date) - $remote).TotalSeconds)
        Write-Host ("Local time {0:HH:mm:ss}, server time {1:HH:mm:ss}, difference about {2:N0} seconds (includes request latency)." -f (Get-Date), $remote, $skew)
        if ($skew -gt 300)     { Add-Result -Area 'Connectivity' -Check 'Clock skew' -Status 'FAIL' -Detail ("About {0:N0} seconds from server time. Over 5 minutes breaks Entra ID / Kerberos / TLS." -f $skew) }
        elseif ($skew -gt 120) { Add-Result -Area 'Connectivity' -Check 'Clock skew' -Status 'WARN' -Detail ("About {0:N0} seconds from server time." -f $skew) }
        else                   { Add-Result -Area 'Connectivity' -Check 'Clock skew' -Status 'PASS' -Detail ("About {0:N0} seconds from server time." -f $skew) }
    } catch {
        Write-Host "Clock check could not complete: $($_.Exception.Message)"
        Add-Result -Area 'Connectivity' -Check 'Clock skew' -Status 'WARN' -Detail 'Could not read a Date header (no HTTPS access to www.microsoft.com on this path), skew not measured.'
    }

    # --- 13c. Build the endpoint list --------------------------------------------
    $endpoints = @()
    # a. Nerdio
    $endpoints += New-Endpoint $gNerdio 'nmwextensions.blob.core.windows.net' 443 $true 'Always' 'Required' 'Nerdio DSC extension'
    $endpoints += New-Endpoint $gNerdio 'catalogartifact.azureedge.net'       443 $true 'Always' 'Required' 'Azure Marketplace'
    # b. Not covered by the Microsoft tool (TCP 1688 cannot carry TLS)
    $endpoints += New-Endpoint $gNoMs 'azkms.core.windows.net' 1688 $false 'Always' 'Required' 'Windows activation (KMS)'
    $endpoints += New-Endpoint $gNoMs 'kms.core.windows.net'   1688 $false 'Always' 'Required' 'Windows activation (KMS), Nerdio KB'
    # d. SSL inspection set (issuer check on key Microsoft endpoints even when the Microsoft tool runs)
    $endpoints += New-Endpoint $gSsl 'login.microsoftonline.com'                443 $true 'Always' 'Required' 'Entra ID authentication' 'Microsoft' $true
    $endpoints += New-Endpoint $gSsl 'rdweb.wvd.microsoft.com'                  443 $true 'Always' 'Required' 'AVD service (representative host for *.wvd.microsoft.com)' 'Microsoft' $true
    $endpoints += New-Endpoint $gSsl 'gcs.prod.monitoring.core.windows.net'     443 $true 'Always' 'Required' 'AVD agent traffic' 'Microsoft' $true
    $endpoints += New-Endpoint $gSsl 'mrsglobalsteus2prod.blob.core.windows.net' 443 $true 'Always' 'Required' 'AVD agent and SXS stack updates' 'Microsoft' $true
    # c. Standard AVD endpoints (fallback)
    $endpoints += New-Endpoint $gStd 'login.microsoftonline.com'                 443 $true  'Fallback' 'Required' 'Entra ID authentication'
    $endpoints += New-Endpoint $gStd 'rdweb.wvd.microsoft.com'                   443 $true  'Fallback' 'Required' 'AVD service (representative host for *.wvd.microsoft.com)'
    $endpoints += New-Endpoint $gStd 'gcs.prod.monitoring.core.windows.net'      443 $true  'Fallback' 'Required' 'AVD agent traffic'
    $endpoints += New-Endpoint $gStd 'mrsglobalsteus2prod.blob.core.windows.net' 443 $true  'Fallback' 'Required' 'AVD agent and SXS stack updates'
    $endpoints += New-Endpoint $gStd 'wvdportalstorageblob.blob.core.windows.net' 443 $true 'Fallback' 'Required' 'Azure portal support'
    $endpoints += New-Endpoint $gStd 'oneocsp.microsoft.com'                      80 $false 'Fallback' 'Required' 'Certificates'
    $endpoints += New-Endpoint $gStd 'www.microsoft.com'                          80 $false 'Fallback' 'Required' 'Certificates'
    $endpoints += New-Endpoint $gStd '169.254.169.254'                            80 $false 'Fallback' 'Required' 'Azure Instance Metadata Service (must not be proxied)'
    $endpoints += New-Endpoint $gStd '168.63.129.16'                              80 $false 'Fallback' 'Required' 'Azure platform / session host health (must not be proxied)'
    $endpoints += New-Endpoint $gStd '168.63.129.16'                           32526 $false 'Fallback' 'Required' 'Azure platform host agent plug-in (Microsoft Learn lists 80 and 32526)'
    # e. Image build (optional)
    if (-not $SkipImageBuildEndpoints) {
        $endpoints += New-Endpoint $gImage 'github.com'                  443 $true 'Always' 'Optional' 'Scripted actions fetch code (for example WVD Optimization)' 'Public'
        $endpoints += New-Endpoint $gImage 'raw.githubusercontent.com'   443 $true 'Always' 'Optional' 'Scripted actions / NVIDIA GPU drivers' 'Public'
        $endpoints += New-Endpoint $gImage 'officecdn.microsoft.com'     443 $true 'Always' 'Optional' 'Office / Microsoft 365 Apps download'
        $endpoints += New-Endpoint $gImage 'download.microsoft.com'      443 $true 'Always' 'Optional' 'Downloads (NVIDIA GPU drivers, Office Deployment Tool)'
        $endpoints += New-Endpoint $gImage 'teams.microsoft.com'         443 $true 'Always' 'Optional' 'Install MS Teams scripted action'
        $endpoints += New-Endpoint $gImage 'support.zoom.us'             443 $true 'Always' 'Optional' 'Install Zoom VDI scripted action (Nerdio KB)' 'Public'
        $endpoints += New-Endpoint $gImage 's3.amazonaws.com'            443 $true 'Always' 'Optional' 'Install ControlUp agent scripted action (Nerdio KB)' 'Public'
    }
    # f. Customer storage
    function ConvertTo-Fqdn { param([string]$Value) $v = ($Value.Trim() -replace '^[a-z]+://', '' -replace '^\\\\', ''); return ($v -split '[\\/:]')[0] }
    if ($FslogixStorageFqdn) { $endpoints += New-Endpoint $gStorage (ConvertTo-Fqdn $FslogixStorageFqdn) 445 $false 'Always' 'Required' 'FSLogix profile storage (SMB)' }
    if ($CssaStorageFqdn)    { $endpoints += New-Endpoint $gStorage (ConvertTo-Fqdn $CssaStorageFqdn)    443 $true  'Always' 'Required' 'NME cssa storage account (AVD agent, FSLogix agent and tools install)' }

    # Decide what to run. 'Always' entries always run. 'Fallback' entries run when the Microsoft tool is not
    # available / usable, or when its output does not mention that host (so a gap in its coverage is not missed).
    $run = @(); $seen = @{}
    foreach ($ep in $endpoints) {
        $key = "$($ep.Endpoint):$($ep.Port)"
        if ($seen.ContainsKey($key)) { continue }
        if ($ep.Mode -eq 'Fallback') {
            if ($toolUsable -and ($toolText -match [regex]::Escape($ep.Endpoint))) { continue }
            if ($toolUsable) { $ep.Source = 'Script (host not listed in Microsoft tool output)' } else { $ep.Source = 'Script (fallback, Microsoft tool not used)' }
        } elseif ($ep.Group -eq $gNerdio -or $ep.Group -eq $gNoMs -or $ep.Group -eq $gSsl) {
            $ep.Source = 'Script (not covered by Microsoft tool / SSL check)'
        }
        $seen[$key] = $true
        $run += $ep
    }

    # --- 13d. Run the tests ------------------------------------------------------
    Write-SubSection "13c. Per-endpoint tests: DNS, TCP, TLS certificate issuer"
    if (-not $script:FullLang) {
        Write-Host "NOTE: Constrained Language Mode - TCP is tested through Test-NetConnection in a job and the"
        Write-Host "certificate issuer CANNOT be captured, so SSL inspection is reported as not determined."
    }
    if ($script:ProxyConfigured) {
        Write-Host "NOTE: a proxy is configured (section 12). Direct tests ignore it."
        if ($script:ProxyStatic) { Write-Host ("      Static proxy {0}:{1} will also be used for an HTTP CONNECT test where a direct connection fails," -f $script:ProxyStatic.Host, $script:ProxyStatic.Port); Write-Host "      and for the SSL inspection hosts even when the direct connection works." }
        elseif ($script:ProxyPac) { Write-Host "      A PAC / auto-detect proxy is in use and cannot be evaluated by this script, so direct failures on" ; Write-Host "      proxy-able ports are reported as WARN (inconclusive), not FAIL." }
    }
    Write-Host ""

    $levels = @{ PASS = 0; WARN = 1; FAIL = 2 }
    foreach ($ep in $run) {
        Write-Host ("Testing {0}:{1}  [{2}] {3}" -f $ep.Endpoint, $ep.Port, $ep.Group, $ep.Purpose)
        $row = New-Obj ([ordered]@{
            Group = $ep.Group; Endpoint = $ep.Endpoint; Port = $ep.Port; Requirement = $ep.Requirement; Source = $ep.Source; Purpose = $ep.Purpose
            Dns = ''; DnsAddresses = ''; Tcp = ''; Path = 'Direct'; TlsHandshake = 'n/a'; TlsProtocol = ''
            CertIssuer = ''; CertSubject = ''; ChainTrusted = ''; ChainRoot = ''; ProxyCertIssuer = ''; SslInspection = 'n/a'
            Status = 'PASS'; Detail = ''
        })
        $notes = @()
        $raise = {
            param([string]$Level, [string]$Message)
            if ($ep.Requirement -eq 'Optional' -and $Level -eq 'FAIL') { $Level = 'WARN' }
            if ($levels[$Level] -gt $levels[$row.Status]) { $row.Status = $Level }
        }

        # DNS
        $dns = Resolve-HostQuiet -HostName $ep.Endpoint
        $row.Dns = if ($dns.Ok) { 'OK' } else { 'FAIL' }
        $row.DnsAddresses = $dns.Addresses
        if (-not $dns.Ok) { $notes += "DNS lookup failed ($($dns.Error))"; & $raise 'WARN' '' }

        # TCP (direct)
        $tcpRes = Test-TcpConnect -HostName $ep.Endpoint -Port $ep.Port
        $row.Tcp = if ($tcpRes.Ok) { 'OK' } elseif ($tcpRes.NotTested) { 'NOT TESTED' } else { 'FAIL' }
        $proxiable = (($ep.Port -eq 443 -or $ep.Port -eq 80) -and ($ep.Endpoint -notmatch '^\d{1,3}(\.\d{1,3}){3}$'))

        $viaProxyOk = $false
        if ($tcpRes.NotTested) {
            $notes += "TCP $($tcpRes.Error)"
            & $raise 'WARN' ''
        } elseif (-not $tcpRes.Ok) {
            $notes += "direct TCP failed ($($tcpRes.Error))"
            if ($script:ProxyConfigured -and $proxiable) {
                if ($script:ProxyStatic -and $ep.Tls -and $script:FullLang) {
                    $px = Get-TlsCertificateInfo -HostName $ep.Endpoint -Port $ep.Port -ProxyHost $script:ProxyStatic.Host -ProxyPort $script:ProxyStatic.Port
                    if ($px.Ok) {
                        $viaProxyOk = $true
                        $row.Path = 'Proxy'; $row.TlsHandshake = 'OK'; $row.TlsProtocol = $px.Protocol; $row.CertIssuer = $px.Issuer; $row.CertSubject = $px.Subject
                        $row.ChainTrusted = "$($px.ChainTrusted)"; $row.ChainRoot = $px.ChainRoot
                        $notes += 'reachable through the proxy only; the AVD agent must use the same proxy (Microsoft recommends bypassing it)'
                        & $raise 'WARN' ''
                    } else {
                        $row.Path = 'Proxy'; $row.TlsHandshake = 'FAIL'
                        $notes += "proxy test also failed ($($px.Error))"
                        & $raise 'FAIL' ''
                    }
                } else {
                    $notes += 'a proxy is configured, so this may be allowed via the proxy; this script cannot test that path here'
                    & $raise 'WARN' ''
                }
            } elseif (($tcpRes.Error -match 'access permissions') -and -not $isAdmin -and ($ep.Endpoint -in '168.63.129.16', '169.254.169.254')) {
                # Azure restricts these platform addresses to administrators, so a non-elevated test is not valid.
                $notes += 'access to this Azure platform address is restricted for non-administrators; re-run elevated to test it'
                & $raise 'WARN' ''
            } else {
                if (-not $dns.Ok) { $notes += 'name does not resolve: check DNS / private DNS zones' }
                & $raise 'FAIL' ''
            }
        }

        # TLS issuer capture (direct)
        if ($tcpRes.Ok -and $ep.Tls) {
            if (-not $script:FullLang) {
                $row.TlsHandshake = 'not tested'; $row.SslInspection = 'Unknown'
                $notes += 'certificate issuer not captured (Constrained Language Mode)'
                & $raise 'WARN' ''
            } else {
                $tls = Get-TlsCertificateInfo -HostName $ep.Endpoint -Port $ep.Port
                if ($tls.Ok) {
                    $row.TlsHandshake = 'OK'; $row.TlsProtocol = $tls.Protocol; $row.CertIssuer = $tls.Issuer; $row.CertSubject = $tls.Subject
                    $row.ChainTrusted = "$($tls.ChainTrusted)"; $row.ChainRoot = $tls.ChainRoot
                } else {
                    $row.TlsHandshake = 'FAIL'
                    $notes += $tls.Error
                    & $raise 'FAIL' ''
                }
            }
        }

        # SSL inspection evaluation on whichever certificate was captured (direct, or via proxy when direct failed)
        if ($row.CertIssuer) {
            $pattern = if ($ep.IssuerSet -eq 'Public') { $issuerPublic } else { $issuerMicrosoft }
            if ($row.CertIssuer -notmatch $pattern) {
                $row.SslInspection = 'YES'
                $notes += "certificate issuer '$($row.CertIssuer)' is not a public CA expected for this endpoint (SSL inspection likely)"
                & $raise 'FAIL' ''
            } else {
                $row.SslInspection = 'No'
                if ($row.ChainTrusted -eq 'False') {
                    $notes += 'issuer looks genuine but the certificate chain is not trusted on this VM (missing root / intermediate, or clock skew)'
                    & $raise 'WARN' ''
                }
            }
        }

        # With a static proxy, also capture the issuer through the proxy for the SSL inspection hosts,
        # because a direct connection that works says nothing about what the proxy does to the agents' traffic.
        if ($ep.SslCheck -and $tcpRes.Ok -and $script:ProxyConfigured -and $script:FullLang) {
            if ($script:ProxyStatic) {
                $px = Get-TlsCertificateInfo -HostName $ep.Endpoint -Port $ep.Port -ProxyHost $script:ProxyStatic.Host -ProxyPort $script:ProxyStatic.Port
                if ($px.Ok) {
                    $row.ProxyCertIssuer = $px.Issuer
                    if ($px.Issuer -notmatch $issuerMicrosoft) {
                        $row.SslInspection = 'YES (via proxy)'
                        $notes += "through the proxy the issuer is '$($px.Issuer)' (SSL inspection by the proxy)"
                        & $raise 'FAIL' ''
                    }
                } else {
                    $notes += "proxy path not testable ($($px.Error))"
                    if ($row.SslInspection -eq 'No') { $row.SslInspection = 'No (direct only)' }
                    & $raise 'WARN' ''
                }
            } else {
                $notes += 'proxy is PAC / auto-detect: the proxy path (and any inspection on it) was not tested'
                if ($row.SslInspection -eq 'No') { $row.SslInspection = 'No (direct only)' }
                & $raise 'WARN' ''
            }
        }

        $row.Detail = ($notes -join '; ')
        Write-Host ("    DNS {0} {1} | TCP {2} | Path {3} | TLS {4} {5}" -f $row.Dns, $row.DnsAddresses, $row.Tcp, $row.Path, $row.TlsHandshake, $row.TlsProtocol)
        if ($row.CertIssuer)      { Write-Host "    Issuer: $($row.CertIssuer)" }
        if ($row.ProxyCertIssuer) { Write-Host "    Issuer via proxy: $($row.ProxyCertIssuer)" }
        if ($row.ChainTrusted)    { Write-Host "    Chain trusted: $($row.ChainTrusted)   Root: $($row.ChainRoot)" }
        Write-Host ("    => {0}{1}" -f $row.Status, $(if ($row.Detail) { " - $($row.Detail)" } else { '' }))
        $connectivityRows += $row

        $checkName = "{0}:{1}  ({2})" -f $row.Endpoint, $row.Port, $(if ($row.Group -like 'Image build*') { 'image build, optional' } else { $row.Group -replace ' \(.*$', '' })
        Add-Result -Area 'Connectivity' -Check $checkName -Status $row.Status -Detail $(if ($row.Detail) { $row.Detail } else { 'Reachable.' })
    }

    # --- 13e. SSL inspection verdict, CSV ----------------------------------------
    Write-SubSection "13d. SSL inspection verdict"
    $captured  = @($connectivityRows | Where-Object { $_.CertIssuer })
    $inspected = @($connectivityRows | Where-Object { $_.SslInspection -like 'YES*' -and $_.Requirement -eq 'Required' })
    $inspectedOptional = @($connectivityRows | Where-Object { $_.SslInspection -like 'YES*' -and $_.Requirement -ne 'Required' })
    $directOnly = @($connectivityRows | Where-Object { $_.SslInspection -eq 'No (direct only)' })
    Write-Host ("Certificate issuer captured on {0} endpoint(s)." -f $captured.Count)
    if ($inspected.Count -gt 0) {
        Write-Host "SSL inspection DETECTED on Microsoft / Nerdio endpoints:"
        $inspected | ForEach-Object { Write-Host ("  {0}:{1}  issuer: {2}" -f $_.Endpoint, $_.Port, $(if ($_.ProxyCertIssuer -and $_.SslInspection -like '*proxy*') { $_.ProxyCertIssuer } else { $_.CertIssuer })) }
        Add-Result -Area 'SSL inspection' -Check 'Certificate issuers' -Status 'FAIL' -Detail ("Non-public-CA issuer on: " + (($inspected | ForEach-Object { $_.Endpoint }) -join ', ') + ". Exclude these endpoints from SSL inspection.")
    } elseif (-not $script:FullLang) {
        Write-Host "Not determined: Constrained Language Mode prevents capturing certificates."
        Add-Result -Area 'SSL inspection' -Check 'Certificate issuers' -Status 'WARN' -Detail 'Not determined (Constrained Language Mode blocks certificate capture).'
    } elseif ($captured.Count -eq 0) {
        Write-Host "Not determined: no TLS handshake completed, so no certificate was seen."
        Add-Result -Area 'SSL inspection' -Check 'Certificate issuers' -Status 'WARN' -Detail 'Not determined: no TLS handshake completed on any endpoint (connectivity blocked or only reachable via a proxy).'
    } elseif ($directOnly.Count -gt 0) {
        Write-Host "No inspection seen on the direct path, but a proxy is configured and its path was not fully tested."
        Add-Result -Area 'SSL inspection' -Check 'Certificate issuers' -Status 'WARN' -Detail ("Direct path shows genuine certificates on {0} endpoint(s), but a proxy is configured and the proxy path was not tested (PAC / auto-detect or tunnel refused)." -f $captured.Count)
    } else {
        Write-Host "No SSL inspection detected on the endpoints where a certificate was captured."
        Add-Result -Area 'SSL inspection' -Check 'Certificate issuers' -Status 'PASS' -Detail ("Genuine public-CA issuers on {0} endpoint(s)." -f $captured.Count)
    }
    if ($inspectedOptional.Count -gt 0) {
        Write-Host "Also intercepted (optional image build endpoints): $((($inspectedOptional | ForEach-Object { $_.Endpoint }) -join ', '))"
    }
    Write-Host "Limits: an inspection device that exempts these names, or inspects by URL category, would not be seen."

    try {
        $csvPath = Join-Path $workDir 'connectivity_results.csv'
        $connectivityRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "Connectivity results written to: connectivity_results.csv (in the ZIP)"
    } catch {
        Write-Host "Could not write connectivity_results.csv: $($_.Exception.Message)"
    }
}

# ---------- 14. Action items for the EDR admin ----------
Write-Section "14. EDR policy review - questions for the EDR admin"
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

# ---------- 15. Summary ----------
Write-Section "15. Summary (PASS / WARN / FAIL)"
if (-not $TestConnectivity) {
    Write-Host "Connectivity, Microsoft URL tool and SSL inspection were NOT tested (run with -TestConnectivity)."
    Write-Host ""
}
# Never report a clean result for a check that silently did not run (for example after an error in a
# restricted session): every check below must have recorded a result by now.
$expectedChecks = @('PowerShell language mode', 'Execution policy', 'AppLocker', 'WinRM', 'Proxy')
if ($TestConnectivity) { $expectedChecks += 'Microsoft URL tool', 'Certificate issuers' }
foreach ($c in $expectedChecks) {
    if (-not ($script:Results | Where-Object { $_.Check -eq $c })) {
        Add-Result -Area 'Script' -Check $c -Status 'WARN' -Detail 'This check did not record a result (it failed or was skipped). See the errors earlier in the transcript.'
    }
}
foreach ($area in ($script:Results | Select-Object -ExpandProperty Area -Unique)) {
    Write-Host "[$area]"
    foreach ($r in ($script:Results | Where-Object { $_.Area -eq $area })) {
        $colour = switch ($r.Status) { 'PASS' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
        Write-Host ("  [{0}] {1} - {2}" -f $r.Status, $r.Check, $r.Detail) -ForegroundColor $colour
    }
}
$nPass = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
$nWarn = @($script:Results | Where-Object { $_.Status -eq 'WARN' }).Count
$nFail = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
$overall = if ($nFail -gt 0) { 'FAIL' } elseif ($nWarn -gt 0) { 'WARN' } else { 'PASS' }
Write-Host ""
Write-Host ("Totals: {0} PASS, {1} WARN, {2} FAIL.  Overall: {3}" -f $nPass, $nWarn, $nFail, $overall)
Write-Host "PASS is not proof: EDR console policy, SYSTEM-context behaviour and inspection that exempts these"
Write-Host "endpoints cannot be seen from here. A WARN usually means the result is inconclusive."

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
