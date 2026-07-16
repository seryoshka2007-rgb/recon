@echo off
REM Runs local_recon_suite.py in automatic mode.
REM Must be placed in the same folder as local_recon_suite.py.

setlocal
set SCRIPT_DIR=%~dp0
set SCRIPT_PATH=%SCRIPT_DIR%local_recon_suite.py

if not exist "%SCRIPT_PATH%" (
    echo [Error] local_recon_suite.py not found next to this bat file.
    pause
    exit /b 1
)

python "%SCRIPT_PATH%" --auto --format csv

echo.
echo Done. Press any key to exit.
pause >nul
