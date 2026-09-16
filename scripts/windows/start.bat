@echo off
REM Double-click entry point for Windows: runs start.ps1 with a relaxed,
REM process-scoped execution policy (never changes the user's machine-wide
REM PowerShell policy) so double-clicking this file works even on a fresh
REM Windows install where script execution is disabled by default.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo Le lancement a echoue - voir les messages ci-dessus.
    pause
)
