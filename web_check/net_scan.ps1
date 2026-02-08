<#
.SYNOPSIS
    A simple network scanner to identify live hosts, open ports, and guess OS.

.DESCRIPTION
    This script scans a given IP address, range, or CIDR block.
    It checks for live hosts using ICMP, resolves hostnames, scans for common open ports,
    and attempts to guess the Operating System based on TTL.

.PARAMETER Target
    The target IP address, range (e.g., 192.168.1.1-10), or CIDR (e.g., 192.168.1.0/24).
    Default is the local subnet if possible, otherwise localhost.

.PARAMETER Ports
    A list of ports to scan. Defaults to common Top 20 ports.

.EXAMPLE
    .\net_scan.ps1 -Target "192.168.1.1"
    Scans a single IP.

.EXAMPLE
    .\net_scan.ps1 -Target "192.168.1.1-192.168.1.50" -Ports 80,443,3389
    Scans a range of IPs for specific ports.
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0, Mandatory = $false)]
    [string]$Target = "127.0.0.1",

    [Parameter(Position = 1, Mandatory = $false)]
    [int[]]$Ports = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443)
)

Begin {
    Write-Host "Starting Network Scan..." -ForegroundColor Cyan
    
    function Get-IPRange {
        param([string]$InputTarget)
        # TODO: Implement IP Range / CIDR parsing logic
        # For now, just return the single IP if it matches a simple IP pattern
        if ($InputTarget -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
            return , $InputTarget
        }
        # Placeholder for range/CIDR
        Write-Warning "Range/CIDR parsing not yet implemented. Scanning provided string as literal."
        return , $InputTarget
    }

    function Test-Port {
        param($IP, $Port)
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $Connect = $TcpClient.BeginConnect($IP, $Port, $null, $null)
        $Wait = $Connect.AsyncWaitHandle.WaitOne(100, $false)
        if ($Wait -and $TcpClient.Connected) {
            $TcpClient.EndConnect($Connect)
            $TcpClient.Close()
            return $true
        }
        else {
            return $false
        }
    }
    
    function Get-OSGuess {
        param($TTL)
        if ($TTL -le 64) { return "Linux/Unix/Mac" }
        if ($TTL -le 128) { return "Windows" }
        if ($TTL -le 255) { return "Network Device/Solaris" }
        return "Unknown"
    }
}

Process {
    $IPList = Get-IPRange -InputTarget $Target
    $Results = @()

    foreach ($IP in $IPList) {
        Write-Progress -Activity "Scanning Network" -Status "Checking $IP"
        
        # 1. Ping / Liveness
        try {
            $Ping = Test-Connection -ComputerName $IP -Count 1 -ErrorAction SilentlyContinue
        }
        catch {
            $Ping = $null
        }

        if ($Ping) {
            # 2. Hostname
            try {
                $HostEntry = [System.Net.Dns]::GetHostEntry($IP)
                $Hostname = $HostEntry.HostName
            }
            catch {
                $Hostname = "N/A"
            }

            # 3. OS Detection (TTL)
            $OS = Get-OSGuess -TTL $Ping.ResponseTimeToLive

            # 4. Port Scanning
            $OpenPorts = @()
            foreach ($P in $Ports) {
                if (Test-Port -IP $IP -Port $P) {
                    $OpenPorts += $P
                }
            }

            $ResultObject = [PSCustomObject]@{
                IP        = $IP
                Hostname  = $Hostname
                Status    = "Up"
                OS        = $OS
                OpenPorts = ($OpenPorts -join ", ")
            }
            $Results += $ResultObject
            
            # Real-time feedback
            Write-Host "Found: $IP ($Hostname) - OS: $OS - Ports: $($OpenPorts -join ', ')" -ForegroundColor Green
        }
        else {
            # Optional: Log down hosts? Maybe genericize.
            # For now, ignore down hosts in main output to keep it clean, or generic object.
        }
    }
}

End {
    Write-Host "Scan Complete." -ForegroundColor Cyan
    return $Results
}
