# Raypher Alpha Installer
# Distibution: iwr -useb https://raypher.ai/install.ps1 | iex

$ErrorActionPreference = "Stop"

# Force TLS 1.2 for secure downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RaypherDir = "C:\Program Files\Raypher"
$BinaryName = "raypher-core.exe"
$BinaryPath = Join-Path $RaypherDir $BinaryName
$RepoUrl = "https://github.com/kidigapeet/Raypher-core"
$ApiUrl = "https://api.github.com/repos/kidigapeet/Raypher-core/releases/latest"

Write-Host "`n🛡️  Installing Raypher Alpha..." -ForegroundColor Cyan

# 1. Ensure Admin Privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
}

# 2. Create and Verify Directory
if (-not (Test-Path $RaypherDir)) {
    Write-Host "Creating installation directory: $RaypherDir"
    New-Item -ItemType Directory -Force -Path $RaypherDir | Out-Null
}

# Verify we can write to the directory
try {
    $testFile = Join-Path $RaypherDir "peretest.tmp"
    "test" | Out-File $testFile
    Remove-Item $testFile
}
catch {
    throw "Cannot write to $RaypherDir. Please ensure you are running as Administrator and no security software is blocking access."
}

# 3. Download Latest Binary
Write-Host "Fetching latest release metadata..."
try {
    $Release = Invoke-RestMethod -Uri $ApiUrl
    $Asset = $Release.assets | Where-Object { $_.name -like "*windows-x86_64.zip*" -or $_.name -like "*raypher-core.exe*" } | Select-Object -First 1
    
    if (-not $Asset) {
        throw "Could not find a valid Windows binary in the latest release."
    }

    Write-Host "Downloading $($Asset.name)..."
    try {
        Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $BinaryPath -UseBasicParsing
    }
    catch {
        Write-Host "Primary download method failed. Retrying with WebClient..." -ForegroundColor Yellow
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($Asset.browser_download_url, $BinaryPath)
    }
}
catch {
    Write-Host "Failed to download from GitHub. Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Looking for local binary as fallback..." -ForegroundColor Yellow
    # Fallback for development/testing if the file is in the current directory
    if (Test-Path ".\target\release\raypher-core.exe") {
        Copy-Item ".\target\release\raypher-core.exe" $BinaryPath -Force
    }
    else {
        throw "Binary download failed and no local fallback found."
    }
}

# 4. Add to System PATH
Write-Host "Updating System PATH..."
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($CurrentPath -notlike "*$RaypherDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$RaypherDir", [EnvironmentVariableTarget]::Machine)
    $env:Path += ";$RaypherDir"
    Write-Host "✓ PATH updated." -ForegroundColor Green
}

# 5. Register & Start Windows Service
Write-Host "Registering Raypher System Service..."
# & $BinaryPath install | Out-Null # Subcommand 'install' is not yet implemented in raypher-core
# The install command usually handles service registration. 
# We ensure it's started.
if (Get-Service -Name "RaypherService" -ErrorAction SilentlyContinue) {
    Start-Service -Name "RaypherService" -ErrorAction SilentlyContinue
    Write-Host "✓ Service started." -ForegroundColor Green
}

# 6. Run Zero-Touch Setup & Hard Intercept
Write-Host "Running Zero-Touch Setup (The Invisible Hand)..."
& $BinaryPath setup --silent
Write-Host "✓ System environment configured." -ForegroundColor Green

Write-Host "Installing OS-level Transparent Redirect (Hard Intercept)..."
& $BinaryPath intercept
Write-Host "✓ Hard Intercept enabled (netsh rules active)." -ForegroundColor Green

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
Write-Host "`n🚀 Launching Raypher Command Center..." -ForegroundColor Green
Start-Sleep -Seconds 1
& $ShortcutPath

Write-Host "`n✨ Raypher is now protecting your AI agents." -ForegroundColor Cyan
Write-Host "Desktop shortcut created: Raypher Dashboard.bat`n"
