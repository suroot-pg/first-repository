@echo off
set "URL=%~1"
:: Remove rdp:// prefix
set "URL=%URL:rdp://=%"
:: Remove trailing slash if any
if "%URL:~-1%"=="/" set "URL=%URL:~0,-1%"

:: Launch MSTSC
start mstsc /v:%URL%
