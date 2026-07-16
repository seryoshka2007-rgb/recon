@echo off
chcp 65001 >nul
title Local Recon Suite

if not "%1"=="hide" (
    start /min "" "%~f0" hide
    exit /b
)

cd /d "%~dp0"

if not exist "reports" mkdir "reports"

if not exist "local_recon_suite.exe" (
    echo ERROR: local_recon_suite.exe not found!
    pause
    exit /b 1
)

echo [%date% %time%] Starting Local Recon Suite...
local_recon_suite.exe --auto --format csv

echo.
echo Report saved to: %cd%\reports\
dir /b "reports\*.csv" 2>nul
echo.
pause
exit /b 0
