@echo off
REM Root-level convenience launcher - double-click this file to start
REM LUNATIC-IT SIEM. Thin wrapper around scripts\windows\start.bat, kept
REM at the repository root so it is the first thing visible after cloning
REM or extracting the ZIP, with no need to navigate into scripts\windows.
REM On first successful run it also creates a Desktop shortcut, so every
REM run after that is a plain double-click with no folder to open at all.
call "%~dp0scripts\windows\start.bat" %*
