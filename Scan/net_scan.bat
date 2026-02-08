@echo off
:: Netscan 1.3 Launcher
:: This script launches the PowerShell network scanner with necessary permissions and bypasses execution policy.

echo Starting Netscan 1.3...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0net_scan.ps1" -ExportCSV "Netscan_v1.3_Result.csv" -ExportHTML "Netscan_v1.3_Result.html"

echo.
echo Scan finished.
pause
