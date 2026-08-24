#description: Copies app shortcuts from the All Users Start Menu to the Public Desktop so every user (including first-time logons) sees them. Run once on the golden image before capture/republish.
#execution mode: Individual
#tags: Windows, Image, Shortcuts

<#
Edit $AppNames below to add/remove apps. Each entry is matched against the .lnk base names
found recursively under the All Users Start Menu — no need to know which subfolder an app's
shortcut lives in, or whether it changes between Office/app updates.
#>
param(
    [string[]]$AppNames = @(
        'Word',
        'Excel',
        'PowerPoint'
    )
)

$ErrorActionPreference = 'Stop'

$logDir = 'C:\Windows\Temp\NMWLogs\ScriptedActions'
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path "$logDir\SA-PublicDesktopShortcuts-$(Get-Date -Format 'yyyyMMdd-HHmmss').log" -Append

try {
    $startMenuRoot = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'
    $publicDesktop = 'C:\Users\Public\Desktop'

    Write-Output "Running on: $env:COMPUTERNAME"
    Write-Output "App list: $($AppNames -join ', ')"
    Write-Output "Indexing shortcuts under: $startMenuRoot"

    if (-not (Test-Path $startMenuRoot)) {
        throw "Start Menu Programs folder not found: $startMenuRoot"
    }
    if (-not (Test-Path $publicDesktop)) {
        New-Item -Path $publicDesktop -ItemType Directory -Force | Out-Null
    }

    $allShortcuts = Get-ChildItem -Path $startMenuRoot -Filter '*.lnk' -Recurse -File
    Write-Output "Found $($allShortcuts.Count) .lnk file(s) under the Start Menu."

    $copiedCount = 0

    foreach ($appName in $AppNames) {

        # Exact base-name match first, so "Word" never falls through to "WordPad".
        $match = $allShortcuts | Where-Object { $_.BaseName -eq $appName } | Select-Object -First 1

        if (-not $match) {
            # Fall back to the shortest base name that contains the app name, e.g. "Chrome"
            # matching "Google Chrome.lnk" when there is no exact "Chrome.lnk".
            $match = $allShortcuts |
                Where-Object { $_.BaseName -match [regex]::Escape($appName) } |
                Sort-Object { $_.BaseName.Length } |
                Select-Object -First 1
        }

        if ($match) {
            $destination = Join-Path $publicDesktop $match.Name
            Copy-Item -Path $match.FullName -Destination $destination -Force
            Write-Output "COPIED: $appName -> $($match.Name)"
            $copiedCount++
        } else {
            Write-Output "MISSING: $appName (no matching .lnk found under $startMenuRoot)"
        }
    }

    Write-Output "Public Desktop contents:"
    Get-ChildItem -Path $publicDesktop -Filter '*.lnk' | ForEach-Object { Write-Output " - $($_.Name)" }

    if ($copiedCount -eq 0) {
        throw "Zero shortcuts were copied. Check `$AppNames for typos against the actual .lnk base names."
    }

    Write-Output "Done. $copiedCount of $($AppNames.Count) app(s) copied to Public Desktop."
}
catch {
    Write-Output "ERROR: $_"
    throw
}
finally {
    Stop-Transcript
}
