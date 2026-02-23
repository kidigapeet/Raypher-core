@echo off
title Raypher Command Center
echo.
echo   RAYPHER — Starting Command Center...
echo.

:: Check if the proxy is already running on port 8888
netstat -ano | findstr :8888 | findstr LISTENING >nul
if %errorlevel% equ 0 (
    echo   ℹ️  Raypher Proxy is already running.
) else (
    echo   🚀 Starting Raypher Proxy...
    :: Launch the proxy in a new hidden window
    start /min "Raypher Proxy" "%~dp0target\release\raypher-core.exe" proxy
    :: Wait a moment for it to start
    timeout /t 2 /nobreak >nul
)

echo   🚀 Launching Dashboard UI...
:: Launch the dashboard as a native-looking app window using Edge
start "" "msedge.exe" --app="http://127.0.0.1:8888/dashboard" --window-size=1280,800

echo.
echo   ✅ Dashboard launched!
echo   ℹ️  You can close this window.
timeout /t 5

