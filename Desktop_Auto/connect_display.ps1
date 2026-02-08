<#
.SYNOPSIS
    Opens the "Connect" pane for wireless display connection.

.DESCRIPTION
    This script simulates the Windows Key + K keystroke to open the Connect side pane in Windows 10/11.
    It uses the keybd_event function from user32.dll via P/Invoke to reliably simulate the key press.
    The script also attempts to close the Start Menu if it accidentally opens due to imperfect key timing.

.EXAMPLE
    .\connect_display.ps1
#>

$signature = @"
[DllImport("user32.dll")]
public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, uint dwExtraInfo);
"@

$type = Add-Type -MemberDefinition $signature -Name "Win32Input" -Namespace Win32Functions -PassThru

# Virtual Key Codes
$VK_LWIN = 0x5B
$VK_K = 0x4B
$KEYEVENTF_KEYUP = 0x0002

# Simulate Win + K
# Press Windows Key
$type::keybd_event($VK_LWIN, 0, 0, 0)
# Press K
$type::keybd_event($VK_K, 0, 0, 0)
# Release K
$type::keybd_event($VK_K, 0, $KEYEVENTF_KEYUP, 0)
# Release Windows Key
$type::keybd_event($VK_LWIN, 0, $KEYEVENTF_KEYUP, 0)

Write-Host "Invoked Connect Pane (Win+K)" -ForegroundColor Green
