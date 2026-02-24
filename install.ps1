# Raypher Alpha Installer - Phase 5 (Harden-12)
# Distribution: iwr -useb https://github.com/kidigapeet/Raypher-core/raw/master/install.ps1 | iex

$ErrorActionPreference = "Continue"

# Force secure protocols (TLS 1.1, 1.2, 1.3 if available)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor 3072 -bor 12288

$RaypherDir = "C:\Program Files\Raypher"
$BinaryName = "raypher-core.exe"
$BinaryPath = Join-Path $RaypherDir $BinaryName
$ApiUrl = "https://api.github.com/repos/kidigapeet/Raypher-core/releases"
$BinaryRepoUrl = "https://github.com/kidigapeet/Raypher-core/raw/master/bin/raypher-core.exe"
$UserAgent = "RaypherInstaller/1.2 (Windows; PowerShell)"

Write-Host "Installer Version: Harden-12"

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
if ($svc -and $svc.Status -ne "Stopped") {
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
        if (Test-Path $BinaryPath) { 
            Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue 
        }
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
        
        if (Test-Path $BinaryPath) { 
            Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue 
        }

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
        Write-Host "[WARNING] Release fetch failed. Trying repo download..."
        try {
            if (Test-Path $BinaryPath) { 
                Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue 
            }
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

# Unblock Executable (SmartScreen Bypass)
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

# FIX 1: RUN SETUP BEFORE STARTING THE SERVICE
Write-Host "Running Zero-Touch Setup (Initializing Databases and Certs)..."
try {
    & $BinaryPath setup --silent
    Write-Host "System environment configured."
}
catch {
    Write-Host "[ERROR] Setup failed. The service may lack required configurations."
}

# FIX 2: THE LOCALSYSTEM PROFILE TRAP
Write-Host "Mirroring configurations for LocalSystem Service..."
$UserConfigDir = Join-Path $env:USERPROFILE ".raypher"
$SystemProfileDir = "C:\Windows\System32\config\systemprofile\.raypher"
if (Test-Path $UserConfigDir) {
    if (-not (Test-Path $SystemProfileDir)) { 
        New-Item -Path $SystemProfileDir -ItemType Directory -Force | Out-Null 
    }
    Copy-Item -Path "$UserConfigDir\*" -Destination $SystemProfileDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Configs mirrored to System context."
}

# 5. Register Windows Service
Write-Host "Registering Raypher Service..."
try {
    & $BinaryPath install-service
}
catch {
    Write-Host "[WARNING] Manual registration fallback..."
    $BinPathWithArgs = "`"$BinaryPath`" --service"
    sc.exe create RaypherService binPath= $BinPathWithArgs start= auto DisplayName= "Raypher AI Security Service"
    sc.exe description RaypherService "Raypher AI Discovery and Proxy Service"
}

# FIX 3: EXPLICITLY BOOT THE ENGINE
Write-Host "Booting the Raypher Engine..."
try {
    Start-Service -Name "RaypherService" -ErrorAction Stop
}
catch {
    net start RaypherService 2>$null
}
Start-Sleep -Seconds 3

# 6. Health Check & Intercept
Write-Host "Configuring Transparent Redirect..."
Write-Host "  Waiting for Raypher Proxy to bind to port 8888..."
$HealthCheckPassed = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $Response = Invoke-WebRequest -Uri "http://127.0.0.1:8888/health" -Method Get -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
        if ($Response.StatusCode -eq 200) {
            $HealthCheckPassed = $true
            break
        }
    }
    catch {
        Write-Host "  [.] Waiting... ($($i+1)/10)"
        Start-Sleep -Seconds 2
    }
}

if ($HealthCheckPassed) {
    Write-Host "  Service is ONLINE. Enabling Intercept..."
    try {
        & $BinaryPath intercept
        Write-Host "Intercept enabled."
    }
    catch {
        Write-Host "[WARNING] Intercept failed."
    }
    
    # 7. Create Native Desktop Shortcut (.lnk)
    Write-Host "Creating Desktop shortcut..."
    $DesktopPath = [Environment]::GetFolderPath("Desktop")
    $ShortcutPath = Join-Path $DesktopPath "Raypher Command Center.lnk"
    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "explorer.exe"
        $Shortcut.Arguments = '"http://127.0.0.1:8888/dashboard"'
        $Shortcut.Description = "Raypher AI Security Command Center"
        $Shortcut.IconLocation = "$BinaryPath, 0"
        $Shortcut.Save()
        Write-Host "Native shortcut created."
    }
    catch {
        Write-Host "[WARNING] COM object failed. Creating standard web shortcut..."
        $UrlContent = "[InternetShortcut]
URL=http://127.0.0.1:8888/dashboard"
        $UrlContent | Out-File -FilePath "$DesktopPath\Launch Raypher.url" -Encoding ascii
    }

    # 8. Launch Immediately
    Write-Host "Launching dashboard..."
    Start-Sleep -Seconds 1
    Start-Process "http://127.0.0.1:8888/dashboard"
    Write-Host "Raypher is now protecting your AI agents."
}
else {
    # FIX 4: PREVENT THE BLIND LAUNCH
    Write-Host "![CRITICAL ERROR] The Raypher Engine crashed or failed to bind to port 8888."
    Write-Host "The dashboard cannot be launched because the local server is offline."
    Write-Host "TROUBLESHOOTING STEP:"
    Write-Host "To see exactly why it crashed, open a new PowerShell as Admin and run:"
    Write-Host "    raypher-core proxy"
}

Write-Host "Installation Complete."