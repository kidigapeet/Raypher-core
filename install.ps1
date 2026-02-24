# Raypher Alpha Installer - Phase 5 (Harden-11)
# Distribution: iwr -useb https://github.com/kidigapeet/Raypher-core/raw/master/install.ps1 | iex

$ErrorActionPreference = "Continue"

# Force secure protocols (TLS 1.1, 1.2, 1.3 if available)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor 3072 -bor 12288

$RaypherDir = "C:\Program Files\Raypher"
$BinaryName = "raypher-core.exe"
$BinaryPath = Join-Path $RaypherDir $BinaryName
$ApiUrl = "https://api.github.com/repos/kidigapeet/Raypher-core/releases"
$BinaryRepoUrl = "https://github.com/kidigapeet/Raypher-core/raw/master/bin/raypher-core.exe"
$UserAgent = "RaypherInstaller/1.1 (Windows; PowerShell)"

Write-Host "Installer Version: Harden-11"

# 1. Ensure Admin Privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as Administrator."
    exit
}

# 2. Setup Directory & Stop Existing Service
if (-not (Test-Path $RaypherDir)) {
    Write-Host "Creating installation directory: $RaypherDir"
    New-Item -Path $RaypherDir -ItemType Directory -Force | Out-Null
}

Write-Host "Releasing file locks for raypher-core.exe..."
$svc = Get-Service -Name "RaypherService" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host "  Stopping RaypherService..."
    Stop-Service -Name "RaypherService" -Force -ErrorAction SilentlyContinue
}

Write-Host "  Ensuring no raypher-core processes are active..."
Get-Process -Name "raypher-core" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$ErrorActionPreference = "Stop"

# 3. Download Latest Binary
$LocalBuildPaths = @("$PSScriptRoot\target\release\raypher-core.exe", ".\target\release\raypher-core.exe")
$FoundLocal = $false

foreach ($LB in $LocalBuildPaths) {
    if (Test-Path $LB) {
        Write-Host "[INFO] Fresh local build detected. Applying..."
        if (Test-Path $BinaryPath) { Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue }
        Copy-Item $LB $BinaryPath -Force
        $FoundLocal = $true
        break
    }
}

if (-not $FoundLocal) {
    Write-Host "Fetching latest release metadata..."
    try {
        $Releases = Invoke-RestMethod -Uri $ApiUrl -UserAgent $UserAgent
        $Release = $Releases[0]
        $Asset = $Release.assets | Where-Object { $_.name -like "*raypher-core.exe*" } | Select-Object -First 1
        
        if (Test-Path $BinaryPath) { Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue }

        if ($Asset) {
            Write-Host "Downloading release binary..."
            Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $BinaryPath -UseBasicParsing -UserAgent $UserAgent
        }
        else {
            Write-Host "[INFO] No executable found in release. Falling back to repository binary..."
            Invoke-WebRequest -Uri $BinaryRepoUrl -OutFile $BinaryPath -UseBasicParsing -UserAgent $UserAgent
        }
    }
    catch {
        Write-Host "[WARNING] Release fetch failed (likely API rate limit). Trying repo download..."
        try {
            if (Test-Path $BinaryPath) { Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue }
            Invoke-WebRequest -Uri $BinaryRepoUrl -OutFile $BinaryPath -UseBasicParsing -UserAgent $UserAgent
        }
        catch {
            Write-Host "[WARNING] Retrying with BITS..."
            try {
                Start-BitsTransfer -Source $BinaryRepoUrl -Destination $BinaryPath -UserAgent $UserAgent -ErrorAction Stop
            }
            catch {
                Write-Host "[STATUS] Local fallback..."
                $FallbackPaths = @(".\target\release\raypher-core.exe", ".\raypher-core.exe", "..\target\release\raypher-core.exe")
                $Found = $false
                foreach ($Path in $FallbackPaths) {
                    if (Test-Path $Path) {
                        Copy-Item $Path $BinaryPath -Force
                        $Found = $true
                        break
                    }
                }
                if (-not $Found) { throw "Download failed." }
            }
        }
    }
}

# -> FIX 1: UNBLOCK THE EXECUTABLE TO BYPASS SMARTSCREEN <-
if (Test-Path $BinaryPath) {
    Unblock-File -Path $BinaryPath -ErrorAction SilentlyContinue
}

# 4. Add to System PATH
Write-Host "Updating System PATH..."
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($CurrentPath -notlike "*$RaypherDir*") {
    $NewPath = if ($CurrentPath.EndsWith(";")) { "$CurrentPath$RaypherDir" } else { "$CurrentPath;$RaypherDir" }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::Machine)
    $env:Path += ";$RaypherDir"
}
Write-Host "PATH updated."

# 5. Register & Start Windows Service
Write-Host "Registering Raypher Service..."
try {
    & $BinaryPath install-service
}
catch {
    Write-Host "[WARNING] Manual registration fallback..."
    $BinPathWithArgs = "`"$BinaryPath`" --service"
    sc.exe create RaypherService binPath= $BinPathWithArgs start= auto DisplayName= "Raypher AI Security Service"
    sc.exe description RaypherService "Raypher AI Discovery and Proxy Service"
    net start RaypherService 2>$null
}

# 6. Run Zero-Touch Setup & Hard Intercept
Write-Host "Running Zero-Touch Setup..."
& $BinaryPath setup --silent
Write-Host "System environment configured."

Write-Host "Configuring Transparent Redirect..."
Write-Host "  Health Check..."
$HealthCheckPassed = $false
for ($i = 0; $i -lt 5; $i++) {
    try {
        $Response = Invoke-WebRequest -Uri "http://127.0.0.1:8888/health" -Method Get -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
        if ($Response.StatusCode -eq 200) {
            $HealthCheckPassed = $true
            break
        }
    }
    catch {
        Write-Host "  Waiting for service... ($($i+1)/5)"
        Start-Sleep -Seconds 2
    }
}

if ($HealthCheckPassed) {
    Write-Host "  Service OK. Enabling Intercept..."
    try {
        & $BinaryPath intercept
        Write-Host "Intercept enabled."
    }
    catch {
        Write-Host "[WARNING] Intercept failed."
    }
}
else {
    Write-Host "[CAUTION] Health check failed."
}

# 7. Create Native Desktop Shortcut (.lnk)
Write-Host "Creating Desktop shortcut..."
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Raypher Command Center.lnk"

try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    
    # -> FIX 2: PROPER URL TARGETING FOR SHORTCUTS <-
    $Shortcut.TargetPath = "explorer.exe"
    $Shortcut.Arguments = '"http://127.0.0.1:8888/dashboard"'
    
    $Shortcut.Description = "Raypher AI Security Command Center"
    $Shortcut.IconLocation = "$BinaryPath, 0"
    $Shortcut.Save()
    Write-Host "Shortcut created."
}
catch {
    Write-Host "[WARNING] COM object failed. Creating standard web shortcut..."
    $UrlContent = "[InternetShortcut]`nURL=http://127.0.0.1:8888/dashboard"
    $UrlContent | Out-File -FilePath "$DesktopPath\Launch Raypher.url" -Encoding ascii
}

# 8. Launch Immediately
Write-Host "Launching dashboard..."
Start-Sleep -Seconds 1
Start-Process "http://127.0.0.1:8888/dashboard"

Write-Host "Raypher is now active."
Write-Host "Installation Complete."