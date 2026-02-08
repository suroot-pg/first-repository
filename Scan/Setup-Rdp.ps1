$WrapperPath = "C:\Project\Scan\rdp_wrap.bat"
$RegPath = "HKCU:\Software\Classes\rdp"

try {
    # Create Protocol Key
    New-Item -Path $RegPath -Force | Out-Null
    New-ItemProperty -Path $RegPath -Name "URL Protocol" -Value "" -PropertyType String -Force | Out-Null
    
    # Create Command Key
    $CmdPath = New-Item -Path "$RegPath\shell\open\command" -Force
    
    # Set Command
    $Command = "`"$WrapperPath`" `"%1`""
    New-ItemProperty -Path $CmdPath.PSPath -Name "(default)" -Value $Command -PropertyType String -Force | Out-Null
    
    Write-Host "Success: 'rdp://' protocol registered to $WrapperPath" -ForegroundColor Green
    Write-Host "Now links in the HTML report will launch MSTSC."
}
catch {
    Write-Error "Registry Error: $_"
}
