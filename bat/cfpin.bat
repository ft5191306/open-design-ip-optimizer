@echo off
rem ============================================================
rem  cfhk pin - bat edition entry
rem  All Chinese UI is rendered by PowerShell so the codepage of
rem  cmd never matters. This wrapper stays pure ASCII.
rem ============================================================
chcp 65001 >nul 2>&1
title cfhk pin - bat edition
setlocal EnableExtensions

set "SCRIPT=%~dp0cfpin.ps1"

if not exist "%SCRIPT%" (
  echo.
  echo   cfpin.ps1 not found. Keep cfpin.bat, cfpin.ps1 and cfpin-core.ps1 together.
  echo.
  pause
  exit /b 1
)

if "%~1"=="" goto :MENU

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Action %~1 -KeepOpen
set "CODE=%ERRORLEVEL%"
exit /b %CODE%

:MENU
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "CODE=%ERRORLEVEL%"
exit /b %CODE%
