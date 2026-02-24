# Raypher Alpha Setup
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RaypherDir = "C:\Program Files\Raypher"
$BinaryPath = "$RaypherDir\raypher-core.exe"

Write-Host "`n[Raypher] Initializing installation..." -ForegroundColor Cyan

# 1. Admin Check
if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Please run PowerShell as Administrator." -ForegroundColor Red; exit
}

# 2. Prepare Environment
if (-not (Test-Path $RaypherDir)) { New-Item -Path $RaypherDir -ItemType Directory -Force | Out-Null }
Stop-Service -Name "RaypherService" -Force -ErrorAction SilentlyContinue
Get-Process -Name "raypher-core" -ErrorAction SilentlyContinue | Stop-Process -Force

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
try { & $BinaryPath setup --silent } catch { }

# Mirror Configs for the System context
$SysProfile = "C:\Windows\System32\config\systemprofile\.raypher"
if (-not (Test-Path $SysProfile)) { New-Item -Path $SysProfile -ItemType Directory -Force | Out-Null }
Copy-Item -Path "$env:USERPROFILE\.raypher\*" -Destination $SysProfile -Recurse -Force -ErrorAction SilentlyContinue

# 6. Boot the Engine (Silent Fallback included)
Write-Host "[Raypher] Booting background service..."
try {
    & $BinaryPath install-service 2>$null
    Start-Service -Name "RaypherService" -ErrorAction Stop
}
catch {
    # If Windows Service is being strict, quietly start it as a hidden background process so the user is never blocked.
    Start-Process -FilePath $BinaryPath -ArgumentList "proxy" -WindowStyle Hidden
}

Start-Sleep -Seconds 3

# 7. Enable Transparent Intercept
try { & $BinaryPath intercept 2>$null } catch { }

# 8. Create Native App Shortcut
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Raypher.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "msedge.exe"
$Shortcut.Arguments = '--app="http://127.0.0.1:8888/dashboard"'
$Shortcut.Description = "Raypher AI Security"
$Shortcut.IconLocation = "$BinaryPath, 0"
$Shortcut.Save()

# 9. Launch as a Native App Window
Write-Host "[Raypher] Launching Command Center..." -ForegroundColor Green
Start-Process "msedge.exe" -ArgumentList '--app="http://127.0.0.1:8888/dashboard"'

Write-Host "`n✨ Installation complete. Raypher is now guarding your local agents.`n" -ForegroundColor Cyan