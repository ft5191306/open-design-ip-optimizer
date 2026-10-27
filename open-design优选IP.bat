@echo off
rem ============================================================
rem  open-design IP Optimizer - one-click launcher (no menu)
rem
rem  Content is ASCII-only on purpose: cmd.exe parses .bat with the
rem  system codepage (CP936), so non-ASCII text here breaks parsing.
rem  All Chinese output comes from cf_pin.py (UTF-8 via chcp 65001).
rem
rem  Why this exists:
rem    open-design.ai and its amr-link subdomain were being routed to
rem    Cloudflare LAX, where the international link drops packets badly
rem    (homepage 387KB took 5-53s, TLS handshake timed out at 15-25s,
rem    API /v1 failed outright). Pinning them to a HKG-landing edge IP
rem    gives 0.3s for the page and 0.43s for the API.
rem
rem  What it does: scans Cloudflare ranges for the best HKG IP, checks
rem  every domain's certificate, then rewrites one marked block in the
rem  hosts file. Original hosts is backed up each run.
rem ============================================================
setlocal
cd /d "%~dp0"

rem ---- locate python ----
set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY (where py >nul 2>nul && set "PY=py")
if not defined PY (if exist "C:\Python312\python.exe" set "PY=C:\Python312\python.exe")
if not defined PY (if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe")
if not defined PY goto no_python

if not exist "cf_pin.py" (
    echo.
    echo   [X] cf_pin.py not found next to this file.
    echo       Keep both files in the same folder.
    echo.
    pause
    exit /b 1
)

rem ---- need administrator rights to edit the hosts file ----
if not defined CF_NO_ELEV (
    net session >nul 2>&1
    if errorlevel 1 (
        echo.
        echo   Requesting administrator privileges...
        echo.
        rem ---- same elevation idiom as the cloudflare launcher: re-launch
        rem ---- this very file elevated. Kept identical on purpose -- that
        rem ---- form is proven to work when double-clicked from Explorer.
        powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
        exit /b 0
    )
)

chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
title open-design IP Optimizer

rem ---- pass the FULL domain set on purpose: cf_pin.py replaces the
rem ---- whole managed block, so a shorter list would silently drop
rem ---- the cloudflare.com entries that are already pinned.
rem ---- --redundant 2: one primary + one backup. hosts has no failover
rem ---- until the first IP times out (~21s), so more than two just
rem ---- bloats the file without helping.
%PY% "cf_pin.py" apply --redundant 2 --domains cloudflare.com,www.cloudflare.com,open-design.ai,www.open-design.ai,amr-link.open-design.ai

echo.
pause
exit /b 0

:no_python
echo.
echo   [X] Python 3 not found on this machine.
echo.
echo   Install Python 3 from https://www.python.org/downloads/
echo   and tick "Add python.exe to PATH", then run this file again.
echo.
pause
exit /b 1
