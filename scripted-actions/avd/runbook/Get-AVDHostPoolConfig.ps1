<#
.SYNOPSIS
    Takes a snapshot of one or more AVD host pools from the Azure control plane.

.DESCRIPTION
    Captures host pool settings, RDP properties, scaling plans and schedules, session hosts,
    app groups, workspaces, VM spec (size, OS image, disk, security type, join type),
    networking, storage accounts, and diagnostic settings. Output is saved as a Markdown
    report and a JSON file, and optionally uploaded to a storage account with a SAS download link.

    HOW TO RUN
      Easiest: run from NME (Scripted Actions > Get-AVDHostPoolConfig > Run).
      Fill in ResourceGroup and either HostPoolName or set IncludeAllInResourceGroup=true.
      To get a download link: also fill in StorageAccountName — the script uploads the report
      and prints SAS URLs to the job output.

      Can also be run locally (Connect-AzAccount first) or as a standalone Azure Runbook.
      NOTE: must be an "Azure Runbook" SA type in NME — not "Windows Script".

    TARGET SCOPE (one or both)
      HostPoolName               Single host pool, or comma-separated list (e.g. Pool1,Pool2)
      IncludeAllInResourceGroup  Set to true to snapshot every host pool in the resource group

    OPTIONAL OUTPUT
      StorageAccountName         Storage account to upload the report to (key fetched automatically)
      StorageContainer           Blob container name (default: avd-configs)
      SasDaysValid               Download link validity in days (default: 1)

    OPTIONAL SKIPS (to speed up large pools)
      SkipRbac=true              Skip RBAC role assignment dump (~7 min for large pools)
      SkipNetworking=true        Skip per-host NIC/vnet lookups
      SkipStorage=true           Skip storage account enumeration
      SkipDiagnostics=true       Skip diagnostic settings

.PARAMETER SubscriptionId
    Azure subscription ID containing the host pool. Optional — defaults to the current Az context.

.PARAMETER ResourceGroup
    Resource group containing the host pool(s). Required.

.PARAMETER HostPoolName
    Name of the host pool(s) to snapshot. Comma-separated for multiple (e.g. Pool1,Pool2).
    Optional when IncludeAllInResourceGroup is true.

.PARAMETER IncludeAllInResourceGroup
    Set to true to discover and snapshot every host pool in the resource group.

.PARAMETER StorageAccountName
    Storage account to upload the report to. The script fetches the key automatically.

.PARAMETER StorageContainer
    Blob container for the uploaded report. Defaults to 'avd-configs'.

.PARAMETER SasDaysValid
    How long the SAS download link stays valid in days. Defaults to 1.

.PARAMETER SkipNetworking
    Skip per-session-host NIC/vnet/subnet lookups. Speeds up large pools.

.PARAMETER SkipRbac
    Skip RBAC role assignment dump. Saves ~7 min on pools with many principals.

.PARAMETER SkipStorage
    Skip storage account enumeration in the resource group.

.PARAMETER SkipDiagnostics
    Skip diagnostic settings on host pools.

.PARAMETER NMEUrl
    NME base URL, e.g. https://nme.example.com. Optional. If provided with NMEToken,
    NME endpoints are queried first for additional NME-managed config.

.PARAMETER NMEToken
    NME REST API bearer token. Optional.

.PARAMETER NMEAccountId
    NME account ID (GUID). Required only if NMEUrl/NMEToken are provided.

.PARAMETER OutputDir
    Where to write the JSON + markdown locally. Defaults to the script directory.

.EXAMPLE
    .\Get-AVDHostPoolConfig.ps1 -ResourceGroup RG-AVD-Prod -HostPoolName MyHostPool `
        -StorageAccountName mystorageaccount

.EXAMPLE
    .\Get-AVDHostPoolConfig.ps1 -ResourceGroup RG-AVD-Prod -IncludeAllInResourceGroup $true `
        -StorageAccountName mystorageaccount -SkipRbac $true

.NOTES
    Requires Az modules: Az.Accounts, Az.DesktopVirtualization, Az.Resources, Az.Network, Az.Compute.
    In Runbook mode the Automation Account managed identity needs Reader + WVD Reader on the subscription.
#>

<# Variables:
{
    "SubscriptionId": {
        "Description": "Azure subscription ID. Optional — defaults to the current Az context subscription if omitted.",
        "IsRequired": false,
        "DefaultValue": ""
    },
    "ResourceGroup": {
        "Description": "Resource group containing the host pool.",
        "IsRequired": true,
        "DefaultValue": ""
    },
    "HostPoolName": {
        "Description": "Name of the host pool(s) to snapshot. Comma-separated for multiple (e.g. Pool1,Pool2). Optional when IncludeAllInResourceGroup is true.",
        "IsRequired": false,
        "DefaultValue": ""
    },
    "IncludeAllInResourceGroup": {
        "Description": "Set to 'true' to also dump every other host pool in the same resource group.",
        "IsRequired": false,
        "DefaultValue": "false"
    },
    "NMEUrl": {
        "Description": "NME base URL (e.g. https://nme.example.com). Required for NME API data.",
        "IsRequired": false,
        "DefaultValue": ""
    },
    "NMEToken": {
        "Description": "NME REST API bearer token. Use a secure variable. Required for NME API data.",
        "IsRequired": false,
        "DefaultValue": ""
    },
    "NMEAccountId": {
        "Description": "NME account ID (GUID). Required when NMEUrl and NMEToken are provided.",
        "IsRequired": false,
        "DefaultValue": ""
    },
    "OutputDir": {
        "Description": "Directory to write JSON and markdown output. Defaults to script directory or TEMP.",
        "IsRequired": false,
        "DefaultValue": ""
    },
    "SkipNetworking": {
        "Description": "Set to 'true' to skip per-session-host NIC/vnet lookups. Speeds up large pools.",
        "IsRequired": false,
        "DefaultValue": "false"
    },
    "SkipRbac": {
        "Description": "Set to 'true' to skip RBAC role assignment dump.",
        "IsRequired": false,
        "DefaultValue": "false"
    },
    "SkipStorage": {
        "Description": "Set to 'true' to skip storage account enumeration in the resource group.",
        "IsRequired": false,
        "DefaultValue": "false"
    },
    "SkipDiagnostics": {
        "Description": "Set to 'true' to skip diagnostic settings on host pools.",
        "IsRequired": false,
        "DefaultValue": "false"
    },
    "StorageAccountName": {
        "Description": "Azure storage account name to upload the report to. Optional.",
        "IsRequired": false,
        "DefaultValue": ""
    },
    "StorageContainer": {
        "Description": "Blob container name for report upload. Defaults to 'avd-configs'.",
        "IsRequired": false,
        "DefaultValue": "avd-configs"
    },
    "SasDaysValid": {
        "Description": "SAS token validity in days. Defaults to 1.",
        "IsRequired": false,
        "DefaultValue": "1"
    }
}
#>

# NME injects all variables listed in the Variables block above as script-scope variables
# before this script runs. No param() block — it is incompatible with NME's execution context.
# For local/Cloud Shell use, set the variables manually before running:
#   $SubscriptionId = "..."; $ResourceGroup = "..."; $HostPoolName = "..."

$ErrorActionPreference = 'Stop'
$ProgressPreference   = 'SilentlyContinue'

# Detect Azure Automation Runbook context via the private metadata JobId that
# Automation injects into every runbook sandbox.
$IsRunbook = ($null -ne $PSPrivateMetadata -and $null -ne $PSPrivateMetadata.JobId)

if ($IsRunbook) {
    Write-Output "[i] Azure Automation Runbook detected (JobId: $($PSPrivateMetadata.JobId))."
    # NME authenticates before the script runs using its own service principal — do NOT call
    # Connect-AzAccount -Identity here. The Az context is already set.
    # Pull NMEToken from Automation encrypted variable if not passed as a parameter.
    if (-not $NMEToken) {
        try {
            $NMEToken = Get-AutomationVariable -Name 'NMEToken' -ErrorAction Stop
            Write-Output "[i] NMEToken loaded from Automation variable."
        } catch {
            Write-Output "[!] No 'NMEToken' Automation variable found - NME API calls will be skipped."
        }
    }
}

# Normalise bool-ish values NME may inject as strings — done first so $IncludeAllInResourceGroup
# is available when deciding whether HostPoolName is required.
$SkipNetworking            = $SkipNetworking            -eq $true -or $SkipNetworking            -eq 'true'
$SkipRbac                  = $SkipRbac                  -eq $true -or $SkipRbac                  -eq 'true'
$SkipStorage               = $SkipStorage               -eq $true -or $SkipStorage               -eq 'true'
$SkipDiagnostics           = $SkipDiagnostics           -eq $true -or $SkipDiagnostics           -eq 'true'
$IncludeAllInResourceGroup = $IncludeAllInResourceGroup -eq $true -or $IncludeAllInResourceGroup -eq 'true'
if (-not $StorageContainer) { $StorageContainer = 'avd-configs' }
if (-not $SasDaysValid)     { $SasDaysValid = 1 } else { $SasDaysValid = [int]$SasDaysValid }

# ResourceGroup is always required.
if (-not $ResourceGroup) {
    if ($IsRunbook) { throw "ResourceGroup is required but was not provided." }
    $ResourceGroup = Read-Host "Enter ResourceGroup"
    if (-not $ResourceGroup) { throw "ResourceGroup is required." }
}

# HostPoolName is required unless IncludeAllInResourceGroup is set.
# Accepts a comma-separated list (e.g. "Pool1,Pool2").
if (-not $HostPoolName -and -not $IncludeAllInResourceGroup) {
    if ($IsRunbook) { throw "HostPoolName is required when IncludeAllInResourceGroup is not set." }
    $HostPoolName = Read-Host "Enter HostPoolName"
    if (-not $HostPoolName) { throw "HostPoolName is required." }
}

# SubscriptionId is resolved from Az context after authentication if not provided.

if (-not $OutputDir) { $OutputDir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP } }

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

function Write-Section { param([string]$Title) Write-Host ""; Write-Host "=== $Title ===" -ForegroundColor Cyan }
function Write-Info    { param([string]$Msg)   Write-Host "[i] $Msg" -ForegroundColor Gray }
function Write-Ok      { param([string]$Msg)   Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn2   { param([string]$Msg)   Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Fail    { param([string]$Msg)   Write-Host "[x] $Msg" -ForegroundColor Red }

function Format-ScheduleTime {
    param($t)
    if ($null -eq $t)        { return $null }
    if ($null -ne $t.hour)   { return "$($t.hour):$($t.minute.ToString('D2'))" }
    if ($null -ne $t.time)   { return $t.time }
    return [string]$t
}

function Test-AzReady {
    try {
        $ctx = Get-AzContext -ErrorAction Stop
        if ($null -eq $ctx) {
            $hint = if ($IsRunbook) { 'Ensure the Automation Account has a managed identity with Reader access.' } else { 'Run Connect-AzAccount first.' }
            Write-Warn2 "No Az context found. $hint"
            return $false
        }
        if ($SubscriptionId -and $ctx.Subscription.Id -ne $SubscriptionId) {
            Write-Info "Setting Az context to subscription $SubscriptionId"
            Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        }
        return $true
    } catch {
        $hint = if ($IsRunbook) { 'Ensure the Automation Account has a managed identity with Reader access.' } else { 'Run Connect-AzAccount first.' }
        Write-Warn2 "Az context not ready. $hint ($($_.Exception.Message))"
        return $false
    }
}

function Invoke-NmeApi {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Method = 'GET'
    )
    if (-not $NMEUrl -or -not $NMEToken) { return $null }
    $uri = "$($NMEUrl.TrimEnd('/'))$Path"
    $headers = @{
        Authorization = "Bearer $NMEToken"
        Accept        = 'application/json'
    }
    try {
        Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -ErrorAction Stop
    } catch {
        Write-Warn2 "NME call failed ($Method $Path): $($_.Exception.Message)"
        return $null
    }
}

function ConvertTo-PlainObject {
    # Drops Azure SDK PSCustomObject metadata so JSON is compact.
    param($Obj)
    if ($null -eq $Obj) { return $null }
    $json = $Obj | ConvertTo-Json -Depth 20 -Compress -WarningAction SilentlyContinue
    return ($json | ConvertFrom-Json)
}

# ----------------------------------------------------------------------------
# Resolve host pool list
# ----------------------------------------------------------------------------

if (-not (Test-AzReady)) { throw "Az PowerShell not authenticated. Run Connect-AzAccount." }

if (-not $SubscriptionId) {
    $SubscriptionId = (Get-AzContext).Subscription.Id
    Write-Info "SubscriptionId not provided — using current Az context: $SubscriptionId"
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$targetPools = @()
if ($HostPoolName) {
    $targetPools += @($HostPoolName -split '\s*,\s*' | Where-Object { $_ })
}

if ($IncludeAllInResourceGroup) {
    Write-Section "Discovering all host pools in $ResourceGroup"
    $allInRg = Get-AzWvdHostPool -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
    foreach ($p in $allInRg) {
        if ($targetPools -notcontains $p.Name) { $targetPools += $p.Name }
    }
    Write-Info "Found $($targetPools.Count) host pool(s) total."
}

if ($targetPools.Count -eq 0) { throw "No host pools to process. Provide HostPoolName or set IncludeAllInResourceGroup=true." }

# ----------------------------------------------------------------------------
# Per-host-pool dump
# ----------------------------------------------------------------------------

$allDumps = @()

foreach ($hp in $targetPools) {
    Write-Section "Host pool: $hp"
    $dump = [ordered]@{
        capturedAt        = (Get-Date).ToString('o')
        subscriptionId    = $SubscriptionId
        resourceGroup     = $ResourceGroup
        hostPoolName      = $hp
        source            = 'azure'
        nme               = $null
        hostPool          = $null
        sessionHostConfig = $null
        scalingPlans      = @()
        sessionHosts      = @()
        userSessions      = @()
        appGroups         = @()
        workspaces        = @()
        rbac              = @()
        networking        = @()
        diagnostics       = @()
        rdpProperties     = $null
        tags              = $null
    }

    # ---- NME first (if creds present) -------------------------------------
    if ($NMEUrl -and $NMEToken -and $NMEAccountId) {
        Write-Info "Trying NME REST API first..."
        $dump.source = 'nme+azure'

        $base = "/api/v1/arm/hostpool/$SubscriptionId/$ResourceGroup/$hp"
        $dump.nme = [ordered]@{
            hostPool            = Invoke-NmeApi -Path $base
            autoScale           = Invoke-NmeApi -Path "$base/auto-scale"
            properties          = Invoke-NmeApi -Path "$base/properties"
            sessionHostTemplate = Invoke-NmeApi -Path "$base/session-host-template"
            desktopImage        = Invoke-NmeApi -Path "$base/desktop-image"
        }
        if ($dump.nme.hostPool) { Write-Ok "NME host pool data captured." }
        else                    { Write-Warn2 "NME data unavailable; relying on Azure-direct only." }
    }

    # ---- Azure: host pool -------------------------------------------------
    try {
        $hpObj = Get-AzWvdHostPool -ResourceGroupName $ResourceGroup -Name $hp -ErrorAction Stop
        $dump.hostPool      = ConvertTo-PlainObject $hpObj
        $dump.rdpProperties = $hpObj.CustomRdpProperty
        $dump.tags          = $hpObj.Tag
        Write-Ok "Host pool properties captured ($($hpObj.HostPoolType), $($hpObj.LoadBalancerType), MaxSession=$($hpObj.MaxSessionLimit))."
    } catch {
        Write-Fail "Failed to read host pool: $($_.Exception.Message)"
        $allDumps += $dump
        continue
    }

    # ---- Session Host Configuration (preview / Dynamic Autoscale gating) --
    try {
        if (Get-Command Get-AzWvdActiveSessionHostConfiguration -ErrorAction SilentlyContinue) {
            $shc = Get-AzWvdActiveSessionHostConfiguration -ResourceGroupName $ResourceGroup `
                -HostPoolName $hp -ErrorAction SilentlyContinue
            $dump.sessionHostConfig = ConvertTo-PlainObject $shc
            if ($shc) { Write-Ok "Session Host Configuration present (Dynamic Autoscale eligible)." }
            else      { Write-Info "No Session Host Configuration (Dynamic Autoscale NOT eligible)." }
        } else {
            # Fallback: raw ARM call via Invoke-AzRestMethod (works in Azure Automation)
            $shcPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.DesktopVirtualization/hostPools/$hp/sessionHostConfigurations/default?api-version=2024-04-08-preview"
            try {
                $shcResp = Invoke-AzRestMethod -Path $shcPath -Method GET -ErrorAction Stop
                if ($shcResp.StatusCode -eq 200) {
                    $dump.sessionHostConfig = $shcResp.Content | ConvertFrom-Json
                    Write-Ok "Session Host Configuration captured via raw ARM."
                } else {
                    Write-Info "No Session Host Configuration (HTTP $($shcResp.StatusCode))."
                }
            } catch {
                Write-Info "No Session Host Configuration (or older API version)."
            }
        }
    } catch {
        Write-Warn2 "Session Host Config lookup failed: $($_.Exception.Message)"
    }

    # ---- Scaling plans referencing this host pool -------------------------
    try {
        $allPlans     = Get-AzWvdScalingPlan -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
        $hpResourceId = $hpObj.Id
        foreach ($plan in $allPlans) {
            $refs = $plan.HostPoolReference | Where-Object { $_.HostPoolArmPath -eq $hpResourceId }
            if ($refs) {
                # Re-fetch the plan in its own RG for full schedule data
                $planRg     = ($plan.Id -split '/')[4]
                $planDetail = Get-AzWvdScalingPlan -ResourceGroupName $planRg -Name $plan.Name -ErrorAction SilentlyContinue
                $planObj    = ConvertTo-PlainObject $planDetail

                # Raw ARM GET with preview api-version to capture scalingMethod per schedule
                $scalingMethodRaw = $null
                try {
                    $armPath = "$($plan.Id)?api-version=2024-11-01-preview"
                    $armResp = Invoke-AzRestMethod -Path $armPath -Method GET -ErrorAction Stop
                    if ($armResp.StatusCode -ne 200) {
                        Write-Warn2 "Preview ARM GET returned HTTP $($armResp.StatusCode)"
                    } else {
                        $armBody          = $armResp.Content | ConvertFrom-Json
                        $scalingMethodRaw = ($armBody.properties.schedules | Where-Object { $_.scalingMethod } | Select-Object -First 1).scalingMethod
                        if (-not $scalingMethodRaw -and $armBody.properties.schedules) {
                            $hasDynamic       = $armBody.properties.schedules | Where-Object { $_.createDelete }
                            $scalingMethodRaw = if ($hasDynamic) { 'CreateDeletePowerManage' } else { 'PowerManage' }
                        }
                        if ($armBody.properties.schedules) {
                            $planObj | Add-Member -MemberType NoteProperty -Name schedulesPreviewApi -Value $armBody.properties.schedules -Force
                        }
                    }
                } catch {
                    Write-Warn2 "Preview ARM GET failed (scalingMethod unknown): $($_.Exception.Message)"
                }

                $scalingMethodLabel = switch ($scalingMethodRaw) {
                    'CreateDeletePowerManage' { 'Dynamic autoscaling (preview)' }
                    'PowerManage'             { 'Standard (Power management, GA)' }
                    default                   { if ($scalingMethodRaw) { $scalingMethodRaw } else { 'Unknown (preview API unavailable)' } }
                }
                $planObj | Add-Member -MemberType NoteProperty -Name scalingMethodDetected -Value $scalingMethodLabel -Force

                $dump.scalingPlans += $planObj
                Write-Ok "Scaling plan linked: $($plan.Name) (type=$($plan.HostPoolType), scaling=$scalingMethodLabel)"
            }
        }
        if ($dump.scalingPlans.Count -eq 0) { Write-Info "No scaling plan is assigned to this host pool." }
    } catch {
        Write-Warn2 "Scaling plan lookup failed: $($_.Exception.Message)"
    }

    # ---- Session hosts ----------------------------------------------------
    try {
        $hosts = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroup -HostPoolName $hp -ErrorAction Stop
        foreach ($h in $hosts) {
            $dump.sessionHosts += [ordered]@{
                name            = $h.Name
                status          = $h.Status
                allowNewSession = $h.AllowNewSession
                sessions        = $h.Session
                osVersion       = $h.OSVersion
                sxsStackVersion = $h.SxSStackVersion
                agentVersion    = $h.AgentVersion
                resourceId      = $h.ResourceId
                lastHeartBeat   = $h.LastHeartBeat
                updateState     = $h.UpdateState
                lastUpdateTime  = $h.LastUpdateTime
                assignedUser    = $h.AssignedUser
                friendlyName    = $h.FriendlyName
            }
        }
        Write-Ok "Captured $($hosts.Count) session host(s)."

        # User sessions per host
        foreach ($h in $hosts) {
            $sid = ($h.Name -split '/')[-1]
            try {
                $sessions = Get-AzWvdUserSession -ResourceGroupName $ResourceGroup -HostPoolName $hp -SessionHostName $sid -ErrorAction SilentlyContinue
                foreach ($s in $sessions) {
                    $dump.userSessions += [ordered]@{
                        sessionHost       = $sid
                        userPrincipalName = $s.UserPrincipalName
                        sessionState      = $s.SessionState
                        applicationType   = $s.ApplicationType
                        createTime        = $s.CreateTime
                    }
                }
            } catch {
                Write-Verbose "User session lookup failed for $sid : $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warn2 "Session host enumeration failed: $($_.Exception.Message)"
    }

    # ---- App groups + workspaces ------------------------------------------
    try {
        $appGroups = Get-AzWvdApplicationGroup -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.HostPoolArmPath -eq $hpObj.Id }
        foreach ($ag in $appGroups) {
            $dump.appGroups += [ordered]@{
                name                 = $ag.Name
                description          = $ag.Description
                applicationGroupType = $ag.ApplicationGroupType
                friendlyName         = $ag.FriendlyName
                location             = $ag.Location
                tags                 = $ag.Tag
            }
        }
        Write-Ok "Captured $($appGroups.Count) application group(s)."

        # Workspaces referencing those app groups
        $allWorkspaces = Get-AzWvdWorkspace -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
        foreach ($w in $allWorkspaces) {
            $matchingAg = $w.ApplicationGroupReference | Where-Object { $appGroups.Id -contains $_ }
            if ($matchingAg) {
                $dump.workspaces += [ordered]@{
                    name         = $w.Name
                    location     = $w.Location
                    description  = $w.Description
                    friendlyName = $w.FriendlyName
                    appGroupRefs = $w.ApplicationGroupReference
                }
            }
        }
    } catch {
        Write-Warn2 "App group / workspace lookup failed: $($_.Exception.Message)"
    }

    # ---- RBAC -------------------------------------------------------------
    if (-not $SkipRbac) {
        try {
            $rb = Get-AzRoleAssignment -Scope $hpObj.Id -ErrorAction SilentlyContinue
            foreach ($r in $rb) {
                $dump.rbac += [ordered]@{
                    displayName    = $r.DisplayName
                    signInName     = $r.SignInName
                    objectType     = $r.ObjectType
                    roleDefinition = $r.RoleDefinitionName
                    scope          = $r.Scope
                    principalId    = $r.ObjectId
                }
            }

            if ($dump.rbac.Count -gt 0) {
                $ids      = @($dump.rbac | ForEach-Object { $_.principalId } | Where-Object { $_ } | Select-Object -Unique)
                $resolved = @{}
                $graphOk  = $false

                # Strategy 1: Graph batch via Invoke-AzRestMethod
                try {
                    for ($i = 0; $i -lt $ids.Count; $i += 999) {
                        $batch = $ids[$i..([Math]::Min($i + 998, $ids.Count - 1))]
                        $gBody = @{ ids = $batch; types = @('user','group','servicePrincipal','device') } | ConvertTo-Json -Compress
                        $resp  = Invoke-AzRestMethod -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' `
                                     -Method POST -Payload $gBody -ErrorAction Stop
                        if ($resp.StatusCode -ne 200) { throw "Graph returned HTTP $($resp.StatusCode): $($resp.Content)" }
                        $data = $resp.Content | ConvertFrom-Json
                        foreach ($obj in $data.value) {
                            $name = if ($obj.userPrincipalName) { $obj.userPrincipalName }
                                    elseif ($obj.displayName)   { $obj.displayName }
                                    else                        { $obj.id }
                            $type = switch ($obj.'@odata.type') {
                                '#microsoft.graph.user'             { 'User' }
                                '#microsoft.graph.group'            { 'Group' }
                                '#microsoft.graph.servicePrincipal' { 'ServicePrincipal' }
                                '#microsoft.graph.device'           { 'Device' }
                                default                             { 'Unknown' }
                            }
                            $resolved[$obj.id] = [pscustomobject]@{ name = $name; type = $type }
                        }
                    }
                    $graphOk = $true
                    Write-Ok "Resolved $($resolved.Count)/$($ids.Count) RBAC principal(s) via Graph batch."
                } catch {
                    Write-Warn2 "Graph batch failed ($($_.Exception.Message)) - falling back to Az cmdlets."
                }

                # Strategy 2: Az cmdlets per-principal (slower, no Graph perms needed)
                if (-not $graphOk) {
                    $resolvedCount = 0
                    foreach ($id in $ids) {
                        try {
                            $u = Get-AzADUser -ObjectId $id -ErrorAction SilentlyContinue
                            if ($u) { $resolved[$id] = [pscustomobject]@{ name = $u.UserPrincipalName; type = 'User' }; $resolvedCount++; continue }
                            $g = Get-AzADGroup -ObjectId $id -ErrorAction SilentlyContinue
                            if ($g) { $resolved[$id] = [pscustomobject]@{ name = $g.DisplayName; type = 'Group' }; $resolvedCount++; continue }
                            $sp = Get-AzADServicePrincipal -ObjectId $id -ErrorAction SilentlyContinue
                            if ($sp) { $resolved[$id] = [pscustomobject]@{ name = $sp.DisplayName; type = 'ServicePrincipal' }; $resolvedCount++; continue }
                        } catch {
                            Write-Warn2 "Could not resolve $id : $($_.Exception.Message)"
                        }
                    }
                    Write-Ok "Resolved $resolvedCount/$($ids.Count) RBAC principal(s) via Az cmdlets."
                }

                foreach ($entry in $dump.rbac) {
                    $r = $resolved[$entry.principalId]
                    if ($r) { $entry.displayName = $r.name; $entry.objectType = $r.type }
                    elseif (-not $entry.displayName) { $entry.displayName = $entry.principalId }
                }
            }

            Write-Ok "Captured $($rb.Count) role assignment(s)."
        } catch {
            Write-Warn2 "RBAC lookup failed: $($_.Exception.Message)"
        }
    }

    # ---- Networking (vnet/subnet per session host) ------------------------
    if (-not $SkipNetworking -and $dump.sessionHosts.Count -gt 0) {
        try {
            foreach ($sh in $dump.sessionHosts) {
                if (-not $sh.resourceId) { continue }
                $vm = Get-AzVM -ResourceId $sh.resourceId -ErrorAction SilentlyContinue
                if (-not $vm) { continue }
                $nicId   = $vm.NetworkProfile.NetworkInterfaces[0].Id
                $nic     = Get-AzNetworkInterface -ResourceId $nicId -ErrorAction SilentlyContinue
                if (-not $nic) { continue }
                $ipCfg    = $nic.IpConfigurations[0]
                $subnetId = [string]$ipCfg.Subnet.Id

                # Fetch managed disk for type, size, and VM generation
                $diskObj    = $null
                $osDiskType = [string]$vm.StorageProfile.OsDisk.ManagedDisk.StorageAccountType
                $diskId     = $vm.StorageProfile.OsDisk.ManagedDisk.Id
                if ($diskId) {
                    $diskParts = $diskId -split '/'
                    $diskRg    = $diskParts[4]
                    $diskName  = $diskParts[-1]
                    $diskObj   = Get-AzDisk -ResourceGroupName $diskRg -Name $diskName -ErrorAction SilentlyContinue
                    if ($diskObj -and -not $osDiskType) { $osDiskType = [string]$diskObj.Sku.Name }
                }
                $osDiskSizeGb = $vm.StorageProfile.OsDisk.DiskSizeGB
                if ((-not $osDiskSizeGb -or $osDiskSizeGb -eq 0) -and $diskObj) {
                    $osDiskSizeGb = $diskObj.DiskSizeGB
                }

                # Security profile
                $secType    = [string]$vm.SecurityProfile.SecurityType
                $secureBoot = $vm.SecurityProfile.UefiSettings.SecureBootEnabled
                $vTpm       = $vm.SecurityProfile.UefiSettings.VTpmEnabled
                if (-not $secType) { $secType = 'Standard' }

                # VM generation — from disk (most reliable), then infer from security type
                $vmGen = if ($diskObj -and $diskObj.HyperVGeneration) { [string]$diskObj.HyperVGeneration }
                         elseif ($secType -in @('TrustedLaunch','ConfidentialVM')) { 'V2' }
                         else { 'Unknown' }

                # Image reference
                $imgRef    = $vm.StorageProfile.ImageReference
                $imageInfo = if ($imgRef.Id) {
                    [ordered]@{ source = 'Gallery/Custom'; imageId = [string]$imgRef.Id; exactVersion = [string]$imgRef.ExactVersion }
                } else {
                    [ordered]@{ source = 'Marketplace'; publisher = [string]$imgRef.Publisher; offer = [string]$imgRef.Offer; sku = [string]$imgRef.Sku; version = [string]$imgRef.Version; exactVersion = [string]$imgRef.ExactVersion }
                }

                # Availability zone
                $availZone = if ($vm.Zones -and $vm.Zones.Count -gt 0) { [string]($vm.Zones -join ',') } else { 'None' }

                # Join type
                $joinType   = 'Unknown'
                $joinDomain = $null
                $joinOU     = $null
                $extTypes   = @($vm.Extensions | ForEach-Object { $_.VirtualMachineExtensionType })
                if ($extTypes -contains 'AADLoginForWindows' -or $extTypes -contains 'AADLoginForLinux') {
                    $joinType = 'AzureAD'
                } elseif ($extTypes -contains 'JsonADDomainExtension') {
                    $joinType = 'ADDomainJoined'
                    $domExt   = Get-AzVMExtension -ResourceGroupName $ResourceGroup -VMName $vm.Name `
                                    -Name 'JsonADDomainExtension' -ErrorAction SilentlyContinue
                    if ($domExt -and $domExt.Settings) {
                        $domSettings = $domExt.Settings | ConvertFrom-Json -ErrorAction SilentlyContinue
                        $joinDomain  = [string]$domSettings.Name
                        $joinOU      = [string]$domSettings.OUPath
                    }
                } elseif ($dump.rdpProperties -match 'targetisaadjoined:i:1') {
                    $joinType = 'AzureAD'
                }

                $dump.networking += [ordered]@{
                    sessionHost   = $sh.name
                    vmSize        = $vm.HardwareProfile.VmSize
                    location      = $vm.Location
                    availZone     = $availZone
                    vmGeneration  = $vmGen
                    osDiskType    = $osDiskType
                    osDiskSizeGb  = $osDiskSizeGb
                    securityType  = $secType
                    secureBoot    = $secureBoot
                    vTpm          = $vTpm
                    imageInfo     = $imageInfo
                    joinType      = $joinType
                    joinDomain    = $joinDomain
                    joinOU        = $joinOU
                    nicId         = $nicId
                    privateIp     = $ipCfg.PrivateIpAddress
                    subnetId      = $subnetId
                    nsgId         = $nic.NetworkSecurityGroup.Id
                    acceleratedNet = $nic.EnableAcceleratedNetworking
                }
            }
            Write-Ok "Networking dump complete ($($dump.networking.Count) host(s))."
        } catch {
            Write-Warn2 "Networking lookup failed: $($_.Exception.Message)"
        }
    }

    # ---- Diagnostic settings -----------------------------------------------
    if (-not $SkipDiagnostics) {
        try {
            $diagPath = "$($hpObj.Id)/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
            $diagResp = Invoke-AzRestMethod -Path $diagPath -Method GET -ErrorAction Stop
            if ($diagResp.StatusCode -eq 200) {
                $diagData = ($diagResp.Content | ConvertFrom-Json).value
                foreach ($d in $diagData) {
                    $dump.diagnostics += [ordered]@{
                        name             = $d.name
                        workspaceId      = $d.properties.workspaceId
                        storageAccountId = $d.properties.storageAccountId
                        eventHubName     = $d.properties.eventHubName
                        logs             = @($d.properties.logs  | Where-Object { $_.enabled } | ForEach-Object { $_.category })
                        metrics          = @($d.properties.metrics| Where-Object { $_.enabled } | ForEach-Object { $_.category })
                    }
                }
                Write-Ok "Diagnostic settings: $($dump.diagnostics.Count) setting(s)."
            } else {
                Write-Info "No diagnostic settings (HTTP $($diagResp.StatusCode))."
            }
        } catch {
            Write-Warn2 "Diagnostic settings lookup failed: $($_.Exception.Message)"
        }
    }

    $allDumps += $dump
}

# ----------------------------------------------------------------------------
# Storage accounts (RG-level, collected once)
# ----------------------------------------------------------------------------
$storageAccounts = @()
if (-not $SkipStorage) {
    Write-Section "Storage accounts in $ResourceGroup"
    try {
        $sas = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
        foreach ($sa in $sas) {
            $shares = @()
            try {
                $ctx = New-AzStorageContext -StorageAccountName $sa.StorageAccountName -UseConnectedAccount -ErrorAction SilentlyContinue
                if ($ctx) {
                    $shares = @(Get-AzStorageShare -Context $ctx -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            [ordered]@{
                                name  = $_.Name
                                quota = try { $_.ShareClient.GetProperties().Value.Quota } catch { $null }
                            }
                        })
                }
            } catch {}
            $storageAccounts += [ordered]@{
                name             = $sa.StorageAccountName
                sku              = $sa.Sku.Name
                kind             = $sa.Kind
                location         = $sa.Location
                accessTier       = $sa.AccessTier
                httpsOnly        = $sa.EnableHttpsTrafficOnly
                allowBlobPublic  = $sa.AllowBlobPublicAccess
                fileEndpoint     = [string]$sa.PrimaryEndpoints.File
                fileShares       = $shares
                privateEndpoints = @($sa.PrivateEndpointConnections | ForEach-Object { ($_.PrivateEndpoint.Id -split '/')[-1] })
                tags             = $sa.Tags
            }
        }
        Write-Ok "Found $($storageAccounts.Count) storage account(s)."
    } catch {
        Write-Warn2 "Storage account lookup failed: $($_.Exception.Message)"
    }
}

# ----------------------------------------------------------------------------
# Write outputs
# ----------------------------------------------------------------------------

$fileLabel = if ($targetPools.Count -eq 1) { $targetPools[0] } else { "$ResourceGroup-all" }
$jsonPath = Join-Path $OutputDir "avd-config-$fileLabel-$timestamp.json"
$mdPath   = Join-Path $OutputDir "avd-config-$fileLabel-$timestamp.md"

$allDumps | ConvertTo-Json -Depth 25 | Out-File -FilePath $jsonPath -Encoding utf8
Write-Ok "Wrote JSON: $jsonPath"

# Build markdown summary
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine("# AVD host pool config snapshot")
[void]$md.AppendLine()
[void]$md.AppendLine("Captured: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
[void]$md.AppendLine("Subscription: $SubscriptionId")
[void]$md.AppendLine("Resource group: $ResourceGroup")
[void]$md.AppendLine()

foreach ($d in $allDumps) {
    $hpRaw = $d.hostPool
    [void]$md.AppendLine("## $($d.hostPoolName)")
    [void]$md.AppendLine()
    if (-not $hpRaw) {
        [void]$md.AppendLine("_Could not read host pool, see JSON for errors._")
        continue
    }

    # ---- Host pool basics
    [void]$md.AppendLine("- Type: **$($hpRaw.HostPoolType)** / Load balancer: $($hpRaw.LoadBalancerType)")
    [void]$md.AppendLine("- Location: $($hpRaw.Location)")
    [void]$md.AppendLine("- Max session limit: $($hpRaw.MaxSessionLimit)")
    [void]$md.AppendLine("- Preferred app group type: $($hpRaw.PreferredAppGroupType)")
    [void]$md.AppendLine("- Validation environment: $($hpRaw.ValidationEnvironment)")
    [void]$md.AppendLine("- Start VM on connect: $($hpRaw.StartVMOnConnect)")
    [void]$md.AppendLine("- Public network access: $($hpRaw.PublicNetworkAccess)")
    $shcLine = if ($d.sessionHostConfig) { '**Enabled** (dynamic autoscale eligible)' } else { 'Not enabled' }
    [void]$md.AppendLine("- Session Host Configuration: $shcLine")

    if ($d.tags -and $d.tags.Keys.Count -gt 0) {
        [void]$md.AppendLine("- Tags:")
        foreach ($k in $d.tags.Keys) {
            [void]$md.AppendLine("  - ${k}: $($d.tags[$k])")
        }
    }
    [void]$md.AppendLine()

    # ---- RDP properties
    if ($d.rdpProperties) {
        [void]$md.AppendLine("### RDP properties")
        ($d.rdpProperties -split ';') | Where-Object { $_.Trim() } | ForEach-Object {
            [void]$md.AppendLine("- $($_.Trim())")
        }
        [void]$md.AppendLine()
    }

    # ---- Scaling plans
    [void]$md.AppendLine("### Scaling plans assigned")
    if ($d.scalingPlans.Count -eq 0) {
        [void]$md.AppendLine("_None._")
    } else {
        foreach ($sp in $d.scalingPlans) {
            $method    = if ($sp.scalingMethodDetected) { $sp.scalingMethodDetected } else { 'Unknown' }
            $schedules = @(if ($sp.schedulesPreviewApi) { $sp.schedulesPreviewApi }
                          elseif ($sp.Schedule)         { $sp.Schedule }
                          elseif ($sp.schedules)        { $sp.schedules }
                          else                          { @() })
            $tz = if ($sp.TimeZone) { $sp.TimeZone } elseif ($sp.timeZone) { $sp.timeZone } else { '' }
            [void]$md.AppendLine("- **$($sp.Name)** ($($sp.HostPoolType)) - $($schedules.Count) schedule(s)")
            [void]$md.AppendLine("  - Scaling method: $method")
            if ($tz) { [void]$md.AppendLine("  - Time zone: $tz") }
            foreach ($sched in $schedules) {
                $days = @(if ($sched.DaysOfWeek) { $sched.DaysOfWeek } elseif ($sched.daysOfWeek) { $sched.daysOfWeek }) -join ', '
                $name = if ($sched.Name) { $sched.Name } elseif ($sched.name) { $sched.name } else { 'schedule' }
                [void]$md.AppendLine("  - **$name** ($days)")
                $_t      = if ($sched.rampUpStartTime) { $sched.rampUpStartTime } else { $sched.RampUpStartTime }
                $ruStart  = Format-ScheduleTime $_t
                $ruMin    = if ($null -ne $sched.rampUpMinimumHostsPct)      { $sched.rampUpMinimumHostsPct }      else { $sched.RampUpMinimumHostsPct }
                $ruThresh = if ($null -ne $sched.rampUpCapacityThresholdPct) { $sched.rampUpCapacityThresholdPct } else { $sched.RampUpCapacityThresholdPct }
                $ruLb     = if ($sched.rampUpLoadBalancingAlgorithm)         { $sched.rampUpLoadBalancingAlgorithm } else { $sched.RampUpLoadBalancingAlgorithm }
                if ($ruStart) { [void]$md.AppendLine("    - Ramp-up:   start=$ruStart, minHosts=$ruMin%, capacityThreshold=$ruThresh%, LB=$ruLb") }
                $_t      = if ($sched.peakStartTime) { $sched.peakStartTime } else { $sched.PeakStartTime }
                $pkStart  = Format-ScheduleTime $_t
                $pkThresh = if ($null -ne $sched.peakCapacityThresholdPct) { $sched.peakCapacityThresholdPct } else { $sched.PeakCapacityThresholdPct }
                $pkLb     = if ($sched.peakLoadBalancingAlgorithm)         { $sched.peakLoadBalancingAlgorithm } else { $sched.PeakLoadBalancingAlgorithm }
                $pkThreshDisplay = if ($null -ne $pkThresh -and "$pkThresh" -ne '' -and $pkThresh -ne 0) { "$pkThresh%" } else { 'N/A (max capacity)' }
                if ($pkStart) { [void]$md.AppendLine("    - Peak:      start=$pkStart, capacityThreshold=$pkThreshDisplay, LB=$pkLb") }
                $_t      = if ($sched.rampDownStartTime) { $sched.rampDownStartTime } else { $sched.RampDownStartTime }
                $rdStart  = Format-ScheduleTime $_t
                $rdMin    = if ($null -ne $sched.rampDownMinimumHostsPct)      { $sched.rampDownMinimumHostsPct }      else { $sched.RampDownMinimumHostsPct }
                $rdThresh = if ($null -ne $sched.rampDownCapacityThresholdPct) { $sched.rampDownCapacityThresholdPct } else { $sched.RampDownCapacityThresholdPct }
                $rdStop   = if ($sched.rampDownStopHostsWhen)                  { $sched.rampDownStopHostsWhen }        else { $sched.RampDownStopHostsWhen }
                $rdWait   = if ($null -ne $sched.rampDownWaitTimeMinutes)      { $sched.rampDownWaitTimeMinutes }      else { $sched.RampDownWaitTimeMinutes }
                $rdNotify = if ($sched.rampDownNotificationMessage)            { $sched.rampDownNotificationMessage }  else { $sched.RampDownNotificationMessage }
                if ($rdStart) { [void]$md.AppendLine("    - Ramp-down: start=$rdStart, minHosts=$rdMin%, capacityThreshold=$rdThresh%, stopWhen=$rdStop, waitMins=$rdWait") }
                if ($rdNotify) { [void]$md.AppendLine("    - Ramp-down notification: $rdNotify") }
                $_t     = if ($sched.offPeakStartTime) { $sched.offPeakStartTime } else { $sched.OffPeakStartTime }
                $opStart = Format-ScheduleTime $_t
                $opLb    = if ($sched.offPeakLoadBalancingAlgorithm) { $sched.offPeakLoadBalancingAlgorithm } else { $sched.OffPeakLoadBalancingAlgorithm }
                if ($opStart) { [void]$md.AppendLine("    - Off-peak:  start=$opStart, LB=$opLb") }
            }
        }
    }
    [void]$md.AppendLine()

    # ---- Session hosts
    [void]$md.AppendLine("### Session hosts ($($d.sessionHosts.Count))")
    if ($d.sessionHosts.Count -eq 0) {
        [void]$md.AppendLine("_None._")
    } else {
        foreach ($sh in $d.sessionHosts) {
            $shortName = ($sh.name -split '/')[-1]
            $drain     = -not $sh.allowNewSession
            [void]$md.AppendLine("- **$shortName**")
            [void]$md.AppendLine("  - Status: $($sh.status) | Sessions: $($sh.sessions) | Drain: $drain")
            if ($sh.osVersion)       { [void]$md.AppendLine("  - OS version: $($sh.osVersion)") }
            if ($sh.agentVersion)    { [void]$md.AppendLine("  - Agent version: $($sh.agentVersion)") }
            if ($sh.sxsStackVersion) { [void]$md.AppendLine("  - SxS stack: $($sh.sxsStackVersion)") }
            if ($sh.lastHeartBeat)   { [void]$md.AppendLine("  - Last heartbeat: $($sh.lastHeartBeat)") }
            if ($sh.updateState -and $sh.updateState -ne 'Succeeded') {
                [void]$md.AppendLine("  - Update state: $($sh.updateState) (last: $($sh.lastUpdateTime))")
            }
            if ($sh.assignedUser) { [void]$md.AppendLine("  - Assigned user: $($sh.assignedUser)") }
        }
    }
    [void]$md.AppendLine()

    # ---- User sessions
    if ($d.userSessions.Count -gt 0) {
        [void]$md.AppendLine("### Active user sessions ($($d.userSessions.Count))")
        foreach ($us in $d.userSessions) {
            [void]$md.AppendLine("- $($us.userPrincipalName) on $($us.sessionHost) - $($us.sessionState) ($($us.applicationType))")
        }
        [void]$md.AppendLine()
    }

    # ---- App groups + workspaces
    [void]$md.AppendLine("### App groups")
    foreach ($ag in $d.appGroups) {
        $desc = if ($ag.description) { " - $($ag.description)" } else { '' }
        [void]$md.AppendLine("- $($ag.name) ($($ag.applicationGroupType))$desc")
    }
    [void]$md.AppendLine()

    if ($d.workspaces.Count -gt 0) {
        [void]$md.AppendLine("### Workspaces")
        foreach ($w in $d.workspaces) {
            $wDesc = if ($w.friendlyName) { $w.friendlyName } else { $w.name }
            [void]$md.AppendLine("- $wDesc ($($w.name)) - $($w.location)")
        }
        [void]$md.AppendLine()
    }

    # ---- RBAC
    if (-not $SkipRbac) {
        [void]$md.AppendLine("### RBAC (top 20)")
        $d.rbac | Select-Object -First 20 | ForEach-Object {
            [void]$md.AppendLine("- $($_.roleDefinition): $($_.displayName) [$($_.objectType)]")
        }
        [void]$md.AppendLine()
    }

    # ---- VM provisioning template + networking
    if (-not $SkipNetworking -and $d.networking.Count -gt 0) {

        # Use first host as the template representative
        $tmpl = $d.networking[0]

        [void]$md.AppendLine("### VM provisioning template")
        [void]$md.AppendLine()
        [void]$md.AppendLine("_Derived from $( ($tmpl.sessionHost -split '/')[-1] ). All session hosts in this pool should share the same spec._")
        [void]$md.AppendLine()
        [void]$md.AppendLine("| Setting | Value |")
        [void]$md.AppendLine("|---|---|")
        [void]$md.AppendLine("| VM size | $($tmpl.vmSize) |")
        [void]$md.AppendLine("| Generation | $($tmpl.vmGeneration) |")
        $diskLabel = if ($tmpl.osDiskType) { $tmpl.osDiskType } else { 'unknown' }
        if ($tmpl.osDiskSizeGb) { $diskLabel += " $($tmpl.osDiskSizeGb) GB" }
        [void]$md.AppendLine("| OS disk | $diskLabel |")
        $secLabel = $tmpl.securityType
        if ($null -ne $tmpl.secureBoot) { $secLabel += " (Secure Boot: $($tmpl.secureBoot), vTPM: $($tmpl.vTpm))" }
        [void]$md.AppendLine("| Security | $secLabel |")
        [void]$md.AppendLine("| Availability zone | $($tmpl.availZone) |")
        [void]$md.AppendLine("| Join type | $($tmpl.joinType) |")
        if ($tmpl.joinDomain) { [void]$md.AppendLine("| Domain | $($tmpl.joinDomain) |") }
        if ($tmpl.joinOU)     { [void]$md.AppendLine("| OU path | $($tmpl.joinOU) |") }
        [void]$md.AppendLine()

        [void]$md.AppendLine("#### Image")
        $img = $tmpl.imageInfo
        if ($img) {
            if ($img.source -eq 'Marketplace') {
                [void]$md.AppendLine("- Source: Azure Marketplace")
                [void]$md.AppendLine("- Publisher: $($img.publisher)")
                [void]$md.AppendLine("- Offer: $($img.offer)")
                [void]$md.AppendLine("- SKU: $($img.sku)")
                $ver = if ($img.exactVersion) { $img.exactVersion } elseif ($img.version) { $img.version } else { 'latest' }
                [void]$md.AppendLine("- Version: $ver")
            } else {
                [void]$md.AppendLine("- Source: Shared Image Gallery / Custom")
                [void]$md.AppendLine("- Image ID: $($img.imageId)")
                if ($img.exactVersion) { [void]$md.AppendLine("- Version: $($img.exactVersion)") }
            }
        }
        [void]$md.AppendLine()

        if ($d.nme -and $d.nme.sessionHostTemplate) {
            [void]$md.AppendLine("#### NME session host template")
            [void]$md.AppendLine('```json')
            [void]$md.AppendLine(($d.nme.sessionHostTemplate | ConvertTo-Json -Depth 6 -Compress))
            [void]$md.AppendLine('```')
            [void]$md.AppendLine()
        }
        if ($d.nme -and $d.nme.desktopImage) {
            [void]$md.AppendLine("#### NME desktop image config")
            [void]$md.AppendLine('```json')
            [void]$md.AppendLine(($d.nme.desktopImage | ConvertTo-Json -Depth 6 -Compress))
            [void]$md.AppendLine('```')
            [void]$md.AppendLine()
        }

        [void]$md.AppendLine("### Networking")
        $subnets = $d.networking | Group-Object { [string]$_.subnetId }
        foreach ($s in $subnets) {
            $label = if ($s.Name) { $s.Name } else { '(unknown subnet)' }
            [void]$md.AppendLine("- Subnet: $label ($($s.Count) host(s))")
        }
        foreach ($n in $d.networking) {
            $shortHost = ($n.sessionHost -split '/')[-1]
            [void]$md.AppendLine("  - **$shortHost**: IP=$($n.privateIp), accelNet=$($n.acceleratedNet), zone=$($n.availZone)")
            if ($n.nsgId) { [void]$md.AppendLine("    - NSG: $($n.nsgId)") }
        }
        [void]$md.AppendLine()
    }

    # ---- Diagnostic settings
    if (-not $SkipDiagnostics) {
        [void]$md.AppendLine("### Diagnostic settings")
        if ($d.diagnostics.Count -eq 0) {
            [void]$md.AppendLine("_None configured._")
        } else {
            foreach ($diag in $d.diagnostics) {
                [void]$md.AppendLine("- **$($diag.name)**")
                if ($diag.workspaceId)      { [void]$md.AppendLine("  - Log Analytics workspace: $(($diag.workspaceId -split '/')[-1])") }
                if ($diag.storageAccountId) { [void]$md.AppendLine("  - Storage account: $(($diag.storageAccountId -split '/')[-1])") }
                if ($diag.eventHubName)     { [void]$md.AppendLine("  - Event hub: $($diag.eventHubName)") }
                if ($diag.logs.Count -gt 0)    { [void]$md.AppendLine("  - Logs: $($diag.logs -join ', ')") }
                if ($diag.metrics.Count -gt 0) { [void]$md.AppendLine("  - Metrics: $($diag.metrics -join ', ')") }
            }
        }
        [void]$md.AppendLine()
    }
}

# ---- Storage accounts (RG-level)
if (-not $SkipStorage) {
    [void]$md.AppendLine("## Storage accounts in $ResourceGroup")
    [void]$md.AppendLine()
    if ($storageAccounts.Count -eq 0) {
        [void]$md.AppendLine("_None found._")
    } else {
        foreach ($sa in $storageAccounts) {
            [void]$md.AppendLine("### $($sa.name)")
            [void]$md.AppendLine("")
            [void]$md.AppendLine("| Setting | Value |")
            [void]$md.AppendLine("|---|---|")
            [void]$md.AppendLine("| SKU | $($sa.sku) |")
            [void]$md.AppendLine("| Kind | $($sa.kind) |")
            [void]$md.AppendLine("| Location | $($sa.location) |")
            [void]$md.AppendLine("| Access tier | $($sa.accessTier) |")
            [void]$md.AppendLine("| HTTPS only | $($sa.httpsOnly) |")
            [void]$md.AppendLine("| Blob public access | $($sa.allowBlobPublic) |")
            if ($sa.fileEndpoint) { [void]$md.AppendLine("| File endpoint | $($sa.fileEndpoint) |") }
            [void]$md.AppendLine()
            if ($sa.fileShares.Count -gt 0) {
                [void]$md.AppendLine("**File shares:**")
                foreach ($fs in $sa.fileShares) {
                    $q = if ($fs.quota) { " ($($fs.quota) GB quota)" } else { '' }
                    [void]$md.AppendLine("- $($fs.name)$q")
                }
                [void]$md.AppendLine()
            }
            if ($sa.privateEndpoints.Count -gt 0) {
                [void]$md.AppendLine("**Private endpoints:** $($sa.privateEndpoints -join ', ')")
                [void]$md.AppendLine()
            }
            if ($sa.tags -and $sa.tags.Keys.Count -gt 0) {
                [void]$md.AppendLine("**Tags:**")
                foreach ($k in $sa.tags.Keys) { [void]$md.AppendLine("- ${k}: $($sa.tags[$k])") }
                [void]$md.AppendLine()
            }
        }
    }
}

$md.ToString() | Out-File -FilePath $mdPath -Encoding utf8
Write-Ok "Wrote markdown: $mdPath"

# ---- Blob upload
if ($StorageAccountName) {
    $mdBlobName   = "avd-config-$fileLabel-$timestamp.md"
    $jsonBlobName = "avd-config-$fileLabel-$timestamp.json"
    Write-Output "[i] Uploading to $StorageAccountName/$StorageContainer ..."
    try {
        # Find the storage account's RG (search subscription-wide)
        $saResource = Get-AzResource -ResourceType 'Microsoft.Storage/storageAccounts' `
            -Name $StorageAccountName -ErrorAction Stop | Select-Object -First 1
        if (-not $saResource) { throw "Storage account '$StorageAccountName' not found in subscription $SubscriptionId." }

        # Key-based context — compatible with all Az.Storage versions
        $saKey = (Get-AzStorageAccountKey -ResourceGroupName $saResource.ResourceGroupName `
            -Name $StorageAccountName -ErrorAction Stop)[0].Value
        $ctx = New-AzStorageContext -StorageAccountName $StorageAccountName `
            -StorageAccountKey $saKey -ErrorAction Stop

        New-AzStorageContainer -Name $StorageContainer -Context $ctx -ErrorAction SilentlyContinue | Out-Null

        Set-AzStorageBlobContent -File $mdPath   -Container $StorageContainer -Blob $mdBlobName   -Context $ctx -Force | Out-Null
        Set-AzStorageBlobContent -File $jsonPath -Container $StorageContainer -Blob $jsonBlobName -Context $ctx -Force | Out-Null

        $expiry  = (Get-Date).ToUniversalTime().AddDays($SasDaysValid)
        $mdSas   = New-AzStorageBlobSASToken -Container $StorageContainer -Blob $mdBlobName   -Context $ctx -Permission r -ExpiryTime $expiry -FullUri
        $jsonSas = New-AzStorageBlobSASToken -Container $StorageContainer -Blob $jsonBlobName -Context $ctx -Permission r -ExpiryTime $expiry -FullUri

        Write-Output "[+] Report uploaded. Links valid for $SasDaysValid day(s):"
        Write-Output ""
        Write-Output "Markdown: $mdSas"
        Write-Output "JSON:     $jsonSas"
    } catch {
        Write-Output "[!] Blob upload failed: $($_.Exception.Message)"
        Write-Output "[i] Ensure NME's service principal has Owner or Storage Account Key Operator role on the storage account."
    }
}

Write-Section "Done"
Write-Host "JSON:     $jsonPath"
Write-Host "Markdown: $mdPath"

# Emit markdown to output stream so NME / Azure Automation job output captures it
Write-Output $md.ToString()
