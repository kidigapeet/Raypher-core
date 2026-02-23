# Raypher Alpha Installer - Phase 5 (Harden-1)
# Distribution: iwr -useb https://github.com/kidigapeet/Raypher-core/raw/master/install.ps1 | iex

$ErrorActionPreference = "Stop"

# Force secure protocols (TLS 1.1, 1.2, 1.3 if available)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor 3072 -bor 12288

$RaypherDir = "C:\Program Files\Raypher"
$BinaryName = "raypher-core.exe"
$BinaryPath = Join-Path $RaypherDir $BinaryName
$ApiUrl = "https://api.github.com/repos/kidigapeet/Raypher-core/releases/latest"
$UserAgent = "RaypherInstaller/1.0 (Windows; PowerShell)"

Write-Host "[Raypher] Installing Alpha - v0.5.0-Harden-5"

# 1. Ensure Admin Privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
}

# 2. Setup Directory & Stop Existing Service
if (-not (Test-Path $RaypherDir)) {
    Write-Host "Creating installation directory: $RaypherDir"
    New-Item -Path $RaypherDir -ItemType Directory -Force | Out-Null
}

Write-Host "Releasing file locks for raypher-core.exe..."
# 1. Stop service gracefully
$svc = Get-Service -Name "RaypherService" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Write-Host "  Stopping RaypherService..."
        Stop-Service -Name "RaypherService" -Force -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "  RaypherService is already stopped."
    }
}

# 2. Kill all instances of the process (Force release locks)
Write-Host "  Ensuring no raypher-core processes are active..."
# Use PowerShell native Stop-Process which handles missing processes gracefully with ErrorAction
Get-Process -Name "raypher-core" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Give Windows a moment to release handles
Start-Sleep -Seconds 2

# 3. Download Latest Binary
Write-Host "Fetching latest release metadata..."
try {
    $Release = Invoke-RestMethod -Uri $ApiUrl -UserAgent $UserAgent
    $Asset = $Release.assets | Where-Object { $_.name -like "*windows-x86_64.zip*" -or $_.name -like "*raypher-core.exe*" } | Select-Object -First 1
    
    if (-not $Asset) {
        throw "Could not find a valid Windows binary in the latest release."
    }

    Write-Host "[DEBUG] Asset URL: $($Asset.browser_download_url)"
    
    # Priority 0: Development Fallback (Search for the fresh binary I just built)
    $LocalBuildPaths = @(
        ".\target\release\raypher-core.exe",
        "$HOME\OneDrive\Desktop\Empire\Ideas\Raypher .exe\raypher-phase1-complete-master\target\release\raypher-core.exe",
        "$HOME\Desktop\Empire\Ideas\Raypher .exe\raypher-phase1-complete-master\target\release\raypher-core.exe"
    )
    
    $FoundLocal = $false
    foreach ($LB in $LocalBuildPaths) {
        if (Test-Path $LB) {
            Write-Host "[INFO] Fresh local build detected at $LB. Applying..."
            # Strategy: Move old file to .old if it's still locked, then copy
            if (Test-Path $BinaryPath) {
                Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue
            }
            Copy-Item $LB $BinaryPath -Force
            $FoundLocal = $true
            break
        }
    }

    if (-not $FoundLocal) {
        Write-Host "Downloading $($Asset.name)..."
        # Strategy: Clear path for download
        if (Test-Path $BinaryPath) {
            Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue
        }
        try {
            Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $BinaryPath -UseBasicParsing -UserAgent $UserAgent
        }
        catch {
            Write-Host "[WARNING] Method 1 (WebRequest) failed. Retrying with Method 2 (WebClient)..."
            try {
                $WebClient = New-Object System.Net.WebClient
                $WebClient.Headers.Add("User-Agent", $UserAgent)
                $WebClient.DownloadFile($Asset.browser_download_url, $BinaryPath)
            }
            catch {
                Write-Host "[WARNING] Method 2 (WebClient) failed. Retrying with Method 3 (BITS)..."
                try {
                    Start-BitsTransfer -Source $Asset.browser_download_url -Destination $BinaryPath -UserAgent $UserAgent -ErrorAction Stop
                }
                catch {
                    Write-Host "[WARNING] Method 3 (BITS) failed. Retrying with Method 4 (Native Curl)..."
                    if (Get-Command "curl.exe" -ErrorAction SilentlyContinue) {
                        & curl.exe -L -H "User-Agent: $UserAgent" -o $BinaryPath $Asset.browser_download_url
                        if ($LASTEXITCODE -ne 0) { throw "Curl failed with exit code $LASTEXITCODE" }
                    }
                    else {
                        throw "All download methods failed. Curl not found."
                    }
                }
            }
        }
    }
}
catch {
    Write-Host "![ERROR] GitHub Download Failed: $($_.Exception.Message)"
    if ($_.Exception.InnerException) {
        Write-Host "![DETAIL] $($_.Exception.InnerException.Message)"
    }
    Write-Host "[STATUS] Attempting final local fallback scan..."
    # Deep fallback search
    $FallbackPaths = @(".\target\release\raypher-core.exe", ".\raypher-core.exe", "..\target\release\raypher-core.exe")
    $Found = $false
    foreach ($Path in $FallbackPaths) {
        if (Test-Path $Path) {
            Copy-Item $Path $BinaryPath -Force
            Write-Host "[INFO] Local fallback from $Path successful."
            $Found = $true
            break
        }
    }
    if (-not $Found) {
        throw "Binary download failed and no local fallback found. Please check your internet connection or GitHub availability."
    }
}

# 4. Add to System PATH
Write-Host "Updating System PATH..."
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($CurrentPath -notlike "*$RaypherDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$RaypherDir", [EnvironmentVariableTarget]::Machine)
    $env:Path += ";$RaypherDir"
    Write-Host "✓ PATH updated."
}

# 5. Register & Start Windows Service
Write-Host "Registering Raypher System Service..."
try {
    & $BinaryPath install-service
}
catch {
    Write-Host "[WARNING] Failed to register service via CLI. Trying manual fallback..."
    $BinPathWithArgs = "`"$BinaryPath`" --service"
    sc.exe create RaypherService binPath= $BinPathWithArgs start= auto DisplayName= "Raypher AI Security Service"
    sc.exe description RaypherService "Raypher Shadow AI Discovery & Proxy Service"
    net start RaypherService
}

# 6. Run Zero-Touch Setup & Hard Intercept
Write-Host "Running Zero-Touch Setup (The Invisible Hand)..."
& $BinaryPath setup --silent
Write-Host "✓ System environment configured."

Write-Host "Installing OS-level Transparent Redirect (Hard Intercept)..."
& $BinaryPath intercept
Write-Host "✓ Hard Intercept enabled (netsh rules active)."

# 7. Create Desktop Shortcut (Native App Mode)
Write-Host "Creating Desktop shortcut for Command Center..."
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Raypher Dashboard.bat"

$BatContent = @"
@echo off
title Raypher Command Center
echo.
echo   🛡️  Raypher — Starting Command Center...
echo.

:: Check if the service is running
sc query "RaypherService" | find "RUNNING" >nul
if %errorlevel% neq 0 (
    echo   🚀 Starting Raypher Service...
    net start "RaypherService" >nul
)

echo   🚀 Launching Dashboard UI (App Mode)...
start "" "msedge.exe" --app="http://127.0.0.1:8888/dashboard" --window-size=1280,800

echo.
echo   ✅ Dashboard launched!
timeout /t 3 >nul
exit
"@

$BatContent | Out-File -FilePath $ShortcutPath -Encoding ascii

# 8. Launch Immediately
Write-Host "`n🚀 Launching Raypher Command Center..."
Start-Sleep -Seconds 1
& $ShortcutPath

Write-Host "`n✨ Raypher is now protecting your AI agents."
Write-Host "Desktop shortcut created: Raypher Dashboard.bat`n"
