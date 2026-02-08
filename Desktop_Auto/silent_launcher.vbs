Set WshShell = CreateObject("WScript.Shell")
' Run PowerShell script hidden (0 = vbHide)
WshShell.Run "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\Project\Desktop_Auto\connect_display.ps1""", 0, False
