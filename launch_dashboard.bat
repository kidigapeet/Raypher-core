@echo off
title Raypher Command Center
echo.
echo   RAYPHER — Starting Command Center...
echo.

:: Launch the dashboard as a native-looking app window using Edge
:: --app flag removes the address bar, tabs, and browser chrome
start "" "msedge.exe" --app="http://127.0.0.1:8888/dashboard" --window-size=1280,800

:: This window stays minimized to keep the proxy alive
:: Minimize this console window
powershell -WindowStyle Hidden -Command "Add-Type -Name 'W' -Namespace 'Win' -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool ShowWindow(IntPtr h, int s);'; [Win.W]::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess()).MainWindowHandle, 6)"

:: Keep the proxy running
echo Raypher Proxy is running...
"%~dp0target\release\raypher-core.exe" proxy
