@echo off
rem Test: square window corners (no transparency at all). See CLAUDE.md 10.59-10.60.
cd /d "%~dp0.."
if not exist "dist\menedger.exe" (
    echo dist\menedger.exe not found. Run packaging\build_windows.bat first.
    pause
    exit /b 1
)
start "" "dist\menedger.exe" --square-windows
