@echo off
title Local Recon Suite

cd /d "%~dp0"

if not exist "reports" mkdir "reports"

echo Starting scan...
echo.

local_recon_suite.exe --auto --format csv --out-dir "reports"

echo.
echo Done!
echo.

if exist "reports\*.csv" (
    echo Files in reports folder:
    dir "reports\*.csv"
) else (
    echo No CSV files found!
)

pause