param (
    [string]$Target = "127.0.0.1",
    [int]$Threads = 50
)

# Helper: IP Range Expansion (Simplified)
function Get-IPRange {
    param([string]$InputTarget)
    $IPs = @()
    if ($InputTarget -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$") {
        $BaseIP = [System.Net.IPAddress]::Parse($matches[1])
        $MaskBits = [int]$matches[2]
        $Mask = [uint32]::MaxValue -shl (32 - $MaskBits)
        $Bytes = $BaseIP.GetAddressBytes(); if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
        $BaseInt = [System.BitConverter]::ToUInt32($Bytes, 0)
        $NetworkInt = $BaseInt -band $Mask
        $BroadcastInt = $NetworkInt -bor (-bnot $Mask)
        for ($i = $NetworkInt + 1; $i -lt $BroadcastInt; $i++) {
            $CurrentBytes = [System.BitConverter]::GetBytes($i)
            if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($CurrentBytes) }
            $IPs += [System.Net.IPAddress]::new($CurrentBytes).IPAddressToString
        }
    }
    elseif ($InputTarget -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3})$") {
        $BaseParts = $matches[1] -split "\."
        $Start = [int]$BaseParts[3]
        $End = [int]$matches[2]
        $Prefix = "$($BaseParts[0]).$($BaseParts[1]).$($BaseParts[2])"
        $Start..$End | ForEach-Object { $IPs += "$Prefix.$_" }
    }
    elseif ($InputTarget -match "^\d+\.\d+\.\d+\.\d+$") {
        $IPs += $InputTarget
    }
    return $IPs
}

# Helper: Local Network
function Get-LocalNetwork {
    $IPConfig = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.PrefixOrigin -in "Dhcp", "Manual" } | Select-Object -First 1
    if ($IPConfig) { return "$($IPConfig.IPAddress)/$($IPConfig.PrefixLength)" }
    return "127.0.0.1"
}

$ScanScriptBlock = {
    param($IP)
    $Result = [PSCustomObject]@{ IP = $IP; IsUp = $false; Hostname = ""; TTL = $null }
    
    try {
        $Ping = New-Object System.Net.NetworkInformation.Ping
        $Reply = $Ping.Send($IP, 750)
        if ($Reply.Status -eq "Success") {
            $Result.IsUp = $true
            $Result.TTL = $Reply.Options.Ttl
            try {
                $HostEntry = [System.Net.Dns]::GetHostEntry($IP)
                $Result.Hostname = $HostEntry.HostName
            }
            catch { $Result.Hostname = "" }
        }
    }
    catch {}
    
    return $Result
}

# Main Logic
if (-not $Target) { $Target = Get-LocalNetwork; Write-Output "Auto-Target: $Target" }
$IPList = Get-IPRange -InputTarget $Target
Write-Output "Scanning $($IPList.Count) hosts with $Threads threads..."

$RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$RunspacePool.Open()

$Jobs = @()
foreach ($IP in $IPList) {
    $PS = [powershell]::Create()
    $PS.RunspacePool = $RunspacePool
    $PS.AddScript($ScanScriptBlock).AddArgument($IP) | Out-Null
    $Jobs += New-Object PSObject -Property @{ PS = $PS; Handle = $PS.BeginInvoke() }
}

$Finished = 0
$Results = @()
while ($Finished -lt $Jobs.Count) {
    foreach ($Job in $Jobs) {
        if ($Job.Handle -and $Job.Handle.IsCompleted) {
            $Obj = $Job.PS.EndInvoke($Job.Handle)
            $Job.Handle = $null
            $Finished++
            
            if ($Obj) {
                $Results += $Obj[0]
            }
            $Job.PS.Dispose()
        }
    }
    Start-Sleep -Milliseconds 100
}

$RunspacePool.Close()
$RunspacePool.Dispose()

Write-Output "Done. Found $($Results.Count) results."
$Results | Format-Table
