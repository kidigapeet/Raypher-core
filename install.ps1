# Raypher Setup
# Distribution: iwr -useb https://github.com/kidigapeet/Raypher-core/raw/master/install.ps1 | iex

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor 3072 -bor 12288

Write-Host "`n[Raypher] Initializing installation..." -ForegroundColor Cyan

# 1. Admin Check
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run PowerShell as Administrator." -ForegroundColor Red
    exit
}

# 2. Prepare Environment
$RaypherDir = "C:\Program Files\Raypher"
$BinaryPath = "$RaypherDir\raypher-core.exe"

if (-not (Test-Path $RaypherDir)) { 
    New-Item -Path $RaypherDir -ItemType Directory -Force | Out-Null 
}

Stop-Service -Name "RaypherService" -Force -ErrorAction SilentlyContinue
Get-Process -Name "raypher-core" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 3. Download Core Engine
Write-Host "[Raypher] Downloading core engine..."
try {
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/kidigapeet/Raypher-core/releases"
    $Asset = $Release[0].assets | Where-Object { $_.name -like "*raypher-core.exe*" } | Select-Object -First 1
    Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $BinaryPath -UseBasicParsing
}
catch {
    Invoke-WebRequest -Uri "https://github.com/kidigapeet/Raypher-core/raw/master/bin/raypher-core.exe" -OutFile $BinaryPath -UseBasicParsing
}
Unblock-File -Path $BinaryPath -ErrorAction SilentlyContinue

# 4. Set System Path
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($CurrentPath -notlike "*$RaypherDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$RaypherDir", "Machine")
}

# 5. Configure Security Policies
Write-Host "[Raypher] Configuring security policies..."
try { 
    & $BinaryPath setup --silent 
} 
catch { }

# Mirror Configs for the System context
$SysProfile = "C:\Windows\System32\config\systemprofile\.raypher"
if (-not (Test-Path $SysProfile)) { 
    New-Item -Path $SysProfile -ItemType Directory -Force | Out-Null 
}
Copy-Item -Path "$env:USERPROFILE\.raypher\*" -Destination $SysProfile -Recurse -Force -ErrorAction SilentlyContinue

# 6. Boot the Engine
Write-Host "[Raypher] Booting background service..."
try {
    & $BinaryPath install-service 2>$null
    Start-Service -Name "RaypherService" -ErrorAction Stop
}
catch {
    # Silent Fallback: Run quietly in the background if the Windows Service Manager is strict
    Start-Process -FilePath $BinaryPath -ArgumentList "proxy" -WindowStyle Hidden
}

# Wait for the local server to wake up before launching the UI
Write-Host "[Raypher] Waiting for Command Center to come online..."
for ($i = 0; $i -lt 15; $i++) {
    try {
        $res = Invoke-WebRequest -Uri "http://127.0.0.1:8888/health" -Method Get -TimeoutSec 1 -UseBasicParsing -ErrorAction Stop
        if ($res.StatusCode -eq 200) { break }
    }
    catch {
        Start-Sleep -Seconds 1
    }
}

# 7. Create Native App Shortcut
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Raypher.lnk"

try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = "msedge.exe"
    $Shortcut.Arguments = '--app="http://127.0.0.1:8888/dashboard"'
    $Shortcut.Description = "Raypher AI Security"
    $Shortcut.IconLocation = "$BinaryPath, 0"
    $Shortcut.Save()
}
catch { }

# 8. Launch as a Native App Window
Write-Host "[Raypher] Launching Command Center..." -ForegroundColor Green
Start-Process "msedge.exe" -ArgumentList '--app="http://127.0.0.1:8888/dashboard"'

Write-Host "`nInstallation complete. You can now enable Intercept from the Command Center." -ForegroundColor Cyan
Write-Host "Raypher is now guarding your local agents."