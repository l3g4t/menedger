@echo off
rem Own title bar (minimise/maximise/close drawn by the app), system-rounded corners. See CLAUDE.md 10.33 and 10.64.
cd /d "%~dp0.."
if not exist "dist\menedger.exe" (
    echo dist\menedger.exe not found. Run packaging\build_windows.bat first.
    pause
    exit /b 1
)
start "" "dist\menedger.exe" --custom-frame
