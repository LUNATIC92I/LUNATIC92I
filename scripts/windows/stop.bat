@echo off
REM Double-click entry point for Windows. Pass -RemoveData to also wipe
REM Postgres/Redis/OpenSearch/Grafana volumes, e.g.:
REM   stop.bat -RemoveData
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop.ps1" %*
pause
