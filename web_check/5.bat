@echo off
setlocal
title Web Security Scanner v8.7

set "PS_SCRIPT=%~dp0check.ps1"

:MAIN_MENU
cls
echo.
echo ========================================================
echo   Web Security Scanner v8.7 (Launcher)
echo ========================================================
echo.
echo   [!] Please enter the target domain.
echo   (e.g., google.com)
echo.

set /p TARGET_INPUT="[Input] Address >> "
if "%TARGET_INPUT%"=="" goto MAIN_MENU

set "TARGET_DOMAIN=%TARGET_INPUT%"

if not exist "%PS_SCRIPT%" (
    echo.
    echo [!] Error: check.ps1 not found.
    echo     Please ensure check.ps1 is in the same folder.
    pause
    goto EXIT_TOOL
)

REM Run PowerShell script forcing UTF-8 encoding to support Korean output
powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:TARGET_DOMAIN='%TARGET_DOMAIN%'; Invoke-Expression ((Get-Content -LiteralPath '%PS_SCRIPT%' -Encoding UTF8) -join \"`n\")"

echo.
echo ========================================================
echo.
echo   [?] Select action.
echo   [R] Retry
echo   [X] Exit
echo.

set /p CHOICE="[Select] >> "
if /i "%CHOICE%"=="r" goto MAIN_MENU
if /i "%CHOICE%"=="x" goto EXIT_TOOL
goto MAIN_MENU

:EXIT_TOOL
exit
