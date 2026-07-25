@echo off
setlocal

cd /d "%~dp0"

echo Starting Aether...
echo Press Ctrl+C to stop, or just close this window.
echo.

aether.exe %*

echo.
echo Aether exited (exit code %errorlevel%).
echo This window stays open so you can read any errors above.
pause
