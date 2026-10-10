@echo off
rem Debug run: writes menedger_debug.log into the project folder. See CLAUDE.md 10.35 and 10.41.
cd /d "%~dp0.."
if not exist "dist\menedger.exe" (
    echo dist\menedger.exe not found. Run packaging\build_windows.bat first.
    pause
    exit /b 1
)
set MENEDGER_DEBUG=1
echo Close the app when done. The log will be: %CD%\menedger_debug.log
"dist\menedger.exe"
echo Log: %CD%\menedger_debug.log
pause
