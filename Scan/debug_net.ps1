$ErrorActionPreference = "Continue"

Write-Host "Testing 127.0.0.1 Connection..."
try {
    $Ping = Test-Connection -ComputerName "127.0.0.1" -Count 1 -ErrorAction Stop
    Write-Host "Ping Success: $($Ping.StatusCode) / $($Ping.Status)"
}
catch {
    Write-Error "Ping Failed: $_"
}

Write-Host "Checking ARP Table..."
try {
    $Neighbors = Get-NetNeighbor -AddressFamily IPv4
    $Neighbors | Select-Object IPAddress, LinkLayerAddress | Format-Table
}
catch {
    Write-Warning "Get-NetNeighbor failed. Trying arp -a"
    arp -a
}
