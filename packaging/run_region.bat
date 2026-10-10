@echo off
rem Test: window corners via SetWindowRgn (no layered window). See CLAUDE.md 10.60.
cd /d "%~dp0.."
if not exist "dist\menedger.exe" (
    echo dist\menedger.exe not found. Run packaging\build_windows.bat first.
    pause
    exit /b 1
)
start "" "dist\menedger.exe" --region-corners
