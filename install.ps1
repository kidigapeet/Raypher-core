# Raypher Alpha Installer - Phase 5 (Harden-10)
# Distribution: iwr -useb https://github.com/kidigapeet/Raypher-core/raw/master/install.ps1 | iex

# We set this to Continue initially so cleanup doesn't crash the script
$ErrorActionPreference = "Continue"

# Force secure protocols (TLS 1.1, 1.2, 1.3 if available)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor 3072 -bor 12288

$RaypherDir = "C:\Program Files\Raypher"
$BinaryName = "raypher-core.exe"
$BinaryPath = Join-Path $RaypherDir $BinaryName
# Use the full releases endpoint to support pre-releases/alphas
$ApiUrl = "https://api.github.com/repos/kidigapeet/Raypher-core/releases"
$BinaryRepoUrl = "https://github.com/kidigapeet/Raypher-core/raw/master/bin/raypher-core.exe"
$UserAgent = "RaypherInstaller/1.0 (Windows; PowerShell)"

Write-Host "`n[Raypher] Installing Alpha - v0.5.0-Harden-10"

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

# From here on, critical failures should STOP the script
$ErrorActionPreference = "Stop"

# 3. Download Latest Binary
# Priority 0: Development Fallback (Search for local build)
$LocalBuildPaths = @(
    "$PSScriptRoot\target\release\raypher-core.exe",
    ".\target\release\raypher-core.exe"
)

$FoundLocal = $false
foreach ($LB in $LocalBuildPaths) {
    if (Test-Path $LB) {
        Write-Host "[INFO] Fresh local build detected at $LB. Applying..."
        if (Test-Path $BinaryPath) {
            Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue
        }
        Copy-Item $LB $BinaryPath -Force
        $FoundLocal = $true
        break
    }
}

if (-not $FoundLocal) {
    Write-Host "Fetching latest release metadata (including pre-releases)..."
    try {
        # Grab the newest release (including pre-releases)
        $Releases = Invoke-RestMethod -Uri $ApiUrl -UserAgent $UserAgent
        $Release = $Releases[0]
        
        # STRICT FILTER: Look only for .exe files to avoid ZIP archive corruption
        $Asset = $Release.assets | Where-Object { $_.name -like "*raypher-core.exe*" } | Select-Object -First 1
        
        if (Test-Path $BinaryPath) {
            Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue
        }

        if ($Asset) {
            Write-Host "Downloading $($Asset.name) from releases..."
            Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $BinaryPath -UseBasicParsing -UserAgent $UserAgent
        }
        else {
            Write-Host "[INFO] No release EXE found. Falling back to repository binary..."
            Invoke-WebRequest -Uri $BinaryRepoUrl -OutFile $BinaryPath -UseBasicParsing -UserAgent $UserAgent
        }
    }
    catch {
        Write-Host "[WARNING] Release fetch failed: $($_.Exception.Message). Trying repository direct download..."
        try {
            if (Test-Path $BinaryPath) {
                Move-Item $BinaryPath "$BinaryPath.old" -Force -ErrorAction SilentlyContinue
            }
            Invoke-WebRequest -Uri $BinaryRepoUrl -OutFile $BinaryPath -UseBasicParsing -UserAgent $UserAgent
        }
        catch {
            Write-Host "[WARNING] Method 1 (WebRequest) failed. Retrying with Method 2 (BITS)..."
            try {
                Start-BitsTransfer -Source $BinaryRepoUrl -Destination $BinaryPath -UserAgent $UserAgent -ErrorAction Stop
            }
            catch {
                # Final local fallback scan (last resort)
                Write-Host "[STATUS] Attempting final local fallback scan..."
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
                    throw "Binary download failed and no local fallback found. Please check your internet connection."
                }
            }
        }
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
# 1. Health Check - Ensure the Proxy is actually responding before we trap the network
Write-Host "  Running Pre-Flight Health Check..."
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
        Write-Host "    [.] Waiting for Raypher Proxy to wake up... ($($i+1)/5)"
        Start-Sleep -Seconds 2
    }
}

if ($HealthCheckPassed) {
    Write-Host "  ✓ Proxy Health OK. Enabling Intercept..."
    try {
        & $BinaryPath intercept
        Write-Host "✓ Hard Intercept enabled (netsh rules active)."
    }
    catch {
        Write-Host "![WARNING] Failed to enable intercept: $($_.Exception.Message)"
    }
}
else {
    Write-Host "![CAUTION] Proxy health check FAILED. Skipping Intercept to preserve internet connectivity."
    Write-Host "  (You can enable it later via 'raypher-core intercept' once the service is healthy)."
}

# 7. Create Native Desktop Shortcut (.lnk)
Write-Host "Creating Desktop shortcut for Command Center..."
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $DesktopPath "Raypher Command Center.lnk"

try {
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
    
    # Target the local dashboard URL
    $Shortcut.TargetPath = "http://127.0.0.1:8888/dashboard"
    $Shortcut.Description = "Raypher AI Security Command Center"
    
    # Branded Icon: Use our binary's icon
    $Shortcut.IconLocation = "$BinaryPath, 0"
    $Shortcut.Save()
    Write-Host "✓ Native shortcut created."
}
catch {
    Write-Host "[WARNING] Failed to create native shortcut. Falling back to basic launch file."
    "http://127.0.0.1:8888/dashboard" | Out-File -FilePath "$DesktopPath\Launch Raypher.url"
}

# 8. Launch Immediately
Write-Host "`n🚀 Launching Raypher Command Center in your default browser..."
Start-Sleep -Seconds 1
# Open the URL via the shell to respect the user's default browser settings
Start-Process "http://127.0.0.1:8888/dashboard"

Write-Host "`n✨ Raypher is now protecting your AI agents."
Write-Host "Desktop shortcut created: Raypher Command Center.lnk`n"
