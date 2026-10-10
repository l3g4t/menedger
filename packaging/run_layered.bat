@echo off
rem Old behaviour for comparison: smooth corners via transparent colour (layered window). See CLAUDE.md 10.63.
cd /d "%~dp0.."
if not exist "dist\menedger.exe" (
    echo dist\menedger.exe not found. Run packaging\build_windows.bat first.
    pause
    exit /b 1
)
start "" "dist\menedger.exe" --custom-frame --layered-corners
