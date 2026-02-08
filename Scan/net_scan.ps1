param (
    [string]$Target,
    [int[]]$Ports = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443),
    [string]$ExportCSV,
    [string]$ExportHTML,
    [int]$Threads = 50
)

# --- Helpers ---
function Get-LocalNetwork {
    $IPConfig = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
        $_.InterfaceAlias -notmatch "Loopback" -and $_.PrefixOrigin -in "Dhcp", "Manual"
    } | Sort-Object InterfaceMetric | Select-Object -First 1

    if ($IPConfig) {
        $IP = $IPConfig.IPAddress
        $PrefixLength = $IPConfig.PrefixLength
        return "$IP/$PrefixLength"
    }
    return "127.0.0.1"
}

function Get-IPRange {
    param([string]$InputTarget)
    $IPs = @()
    # CIDR
    if ($InputTarget -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$") {
        $BaseIP = [System.Net.IPAddress]::Parse($matches[1])
        $MaskBits = [int]$matches[2]
        $Mask = [uint32]::MaxValue -shl (32 - $MaskBits)
        $Bytes = $BaseIP.GetAddressBytes()
        if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
        $BaseInt = [System.BitConverter]::ToUInt32($Bytes, 0)
        $NetworkInt = $BaseInt -band $Mask
        $BroadcastInt = $NetworkInt -bor (-bnot $Mask)
        for ($i = $NetworkInt + 1; $i -lt $BroadcastInt; $i++) {
            $CurrentBytes = [System.BitConverter]::GetBytes($i)
            if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($CurrentBytes) }
            $IPs += [System.Net.IPAddress]::new($CurrentBytes).IPAddressToString
        }
    } 
    # Range
    elseif ($InputTarget -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$") {
        $StartParts = $matches[1] -split "\."
        $EndParts = $matches[2] -split "\."
        if ("$($StartParts[0]).$($StartParts[1]).$($StartParts[2])" -eq "$($EndParts[0]).$($EndParts[1]).$($EndParts[2])") {
            $Start = [int]$StartParts[3]
            $End = [int]$EndParts[3]
            $Prefix = "$($StartParts[0]).$($StartParts[1]).$($StartParts[2])"
            $Start..$End | ForEach-Object { $IPs += "$Prefix.$_" }
        }
        else {
            $IPs += $matches[1]
            $IPs += $matches[2]
        }
    }
    # Simple Range (Last Octet)
    elseif ($InputTarget -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3})$") {
        $BaseParts = $matches[1] -split "\."
        $Start = [int]$BaseParts[3]
        $End = [int]$matches[2]
        $Prefix = "$($BaseParts[0]).$($BaseParts[1]).$($BaseParts[2])"
        $Start..$End | ForEach-Object { $IPs += "$Prefix.$_" }
    }
    # Single IP
    elseif ($InputTarget -match "^\d+\.\d+\.\d+\.\d+$") {
        $IPs += $InputTarget
    }
    else {
        if (-not $InputTarget) { return @() }
        $IPs += $InputTarget 
    }
    return $IPs
}

# --- Main Execution ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Write-Output "=========================================="
Write-Output " Netscan 1.3 (Final Release)"
Write-Output "=========================================="

if (-not $Target) { 
    $Target = Get-LocalNetwork
    Write-Output "Auto-Target: $Target"
}

$IPList = Get-IPRange -InputTarget $Target
if ($IPList.Count -eq 0) {
    Write-Warning "No IPs to scan."
    exit
}

Write-Output "Scanning $($IPList.Count) hosts with $Threads threads..."

# Pre-fetch ARP
$ArpTable = @{}
try {
    $NetNeighbor = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue 
    foreach ($N in $NetNeighbor) { $ArpTable[$N.IPAddress] = $N.LinkLayerAddress }
}
catch {
    $ArpOutput = arp -a
    foreach ($Line in $ArpOutput) {
        if ($Line -match "\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+") {
            $ArpTable[$matches[1]] = $matches[2].ToUpper().Replace("-", ":")
        }
    }
}

# Add Local Interface MACs (Self)
try {
    $LocalAdapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    foreach ($Adapter in $LocalAdapters) {
        $Mac = $Adapter.MacAddress.Replace("-", ":")
        $IPs = Get-NetIPAddress -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($IP in $IPs) {
            if (-not $ArpTable.ContainsKey($IP.IPAddress)) {
                $ArpTable[$IP.IPAddress] = $Mac
            }
        }
    }
}
catch {}

$VendorOUI = @{
    # --- Virtualization ---
    "00:0C:29" = "VMware"; "00:50:56" = "VMware"; "00:05:69" = "VMware"
    "00:15:5D" = "Microsoft (Hyper-V)"
    "00:16:3E" = "Xensource"
    "08:00:27" = "PCS Systemtechnik (VirtualBox)"
    
    # --- Mobile (Samsung) ---
    "00:16:32" = "Samsung"; "00:12:47" = "Samsung"; "00:15:99" = "Samsung"
    "00:17:C9" = "Samsung"; "00:18:AF" = "Samsung"; "00:19:15" = "Samsung"
    "00:1B:98" = "Samsung"; "00:1C:43" = "Samsung"; "00:1D:25" = "Samsung"
    "00:1E:E2" = "Samsung"; "00:1F:CC" = "Samsung"; "00:21:19" = "Samsung"
    "00:23:D7" = "Samsung"; "00:24:54" = "Samsung"; "00:24:90" = "Samsung"
    "00:26:37" = "Samsung"; "00:2F:36" = "Samsung"; "04:18:0F" = "Samsung"
    "0C:D9:C1" = "Samsung"; "10:1D:C0" = "Samsung"; "10:77:17" = "Samsung"
    "14:49:E0" = "Samsung"; "18:3F:47" = "Samsung"; "1C:5A:3E" = "Samsung"
    "20:D5:BF" = "Samsung"; "24:74:96" = "Samsung"; "28:98:7B" = "Samsung"
    "2C:44:01" = "Samsung"; "30:CD:A7" = "Samsung"; "34:14:5F" = "Samsung"
    "38:2D:E8" = "Samsung"; "3C:62:00" = "Samsung"; "40:0E:85" = "Samsung"
    "44:F4:59" = "Samsung"; "48:44:F7" = "Samsung"; "4C:BC:A5" = "Samsung"
    "50:01:D9" = "Samsung"; "50:B7:C3" = "Samsung"; "54:05:DB" = "Samsung"
    "58:C5:F6" = "Samsung"; "5C:A3:9D" = "Samsung"; "60:6C:66" = "Samsung"
    "64:B3:10" = "Samsung"; "68:05:71" = "Samsung"; "6C:83:36" = "Samsung"
    "70:86:14" = "Samsung"; "74:5A:B6" = "Samsung"; "78:47:1D" = "Samsung"
    "78:D6:F0" = "Samsung"; "7C:0B:C6" = "Samsung"; "80:18:44" = "Samsung"
    "84:25:DB" = "Samsung"; "84:38:38" = "Samsung"; "84:55:A5" = "Samsung"
    "88:32:9B" = "Samsung"; "8C:71:F8" = "Samsung"; "8C:77:12" = "Samsung"
    "90:18:7C" = "Samsung"; "94:63:D6" = "Samsung"; "98:1D:64" = "Samsung"
    "9C:02:98" = "Samsung"; "A0:21:95" = "Samsung"; "A0:CB:FD" = "Samsung"
    "A4:75:B9" = "Samsung"; "A8:06:00" = "Samsung"; "AC:36:13" = "Samsung"
    "B0:C4:E7" = "Samsung"; "B4:07:F9" = "Samsung"; "B8:5E:7B" = "Samsung"
    "BC:20:A4" = "Samsung"; "C0:BD:D1" = "Samsung"; "C4:42:02" = "Samsung"
    "C8:19:F7" = "Samsung"; "CC:07:AB" = "Samsung"; "CC:3A:61" = "Samsung"
    "D0:17:6A" = "Samsung"; "D0:DF:C7" = "Samsung"; "D4:87:D8" = "Samsung"
    "D8:31:CF" = "Samsung"; "D8:57:EF" = "Samsung"; "DC:71:44" = "Samsung"
    "E0:99:71" = "Samsung"; "E4:58:B8" = "Samsung"; "E4:7C:F9" = "Samsung"
    "E8:3A:12" = "Samsung"; "E8:50:8B" = "Samsung"; "E8:E5:D6" = "Samsung"
    "EC:1F:72" = "Samsung"; "EC:E0:9B" = "Samsung"; "F0:25:B7" = "Samsung"
    "F0:6B:CA" = "Samsung"; "F0:E2:33" = "Samsung"; "F4:09:D8" = "Samsung"
    "F4:7B:5E" = "Samsung"; "F4:9F:54" = "Samsung"; "F4:D9:FB" = "Samsung"
    "F8:04:2E" = "Samsung"; "FC:C7:34" = "Samsung"

    # --- Mobile (Apple) ---
    "00:03:93" = "Apple"; "00:05:02" = "Apple"; "00:0A:27" = "Apple"
    "00:0A:95" = "Apple"; "00:0D:93" = "Apple"; "00:10:FA" = "Apple"
    "00:11:24" = "Apple"; "00:14:51" = "Apple"; "00:16:CB" = "Apple"
    "00:17:F2" = "Apple"; "00:19:E3" = "Apple"; "00:1B:63" = "Apple"
    "00:1C:B3" = "Apple"; "00:1D:4F" = "Apple"; "00:1E:52" = "Apple"
    "00:1E:C2" = "Apple"; "00:1F:5B" = "Apple"; "00:1F:F3" = "Apple"
    "00:21:E9" = "Apple"; "00:22:41" = "Apple"; "00:23:12" = "Apple"
    "00:23:32" = "Apple"; "00:23:6C" = "Apple"; "00:23:DF" = "Apple"
    "00:24:36" = "Apple"; "00:25:00" = "Apple"; "00:25:4B" = "Apple"
    "00:26:08" = "Apple"; "00:26:4A" = "Apple"; "00:26:B0" = "Apple"
    "00:26:BB" = "Apple"; "04:69:F8" = "Apple"; "04:DB:56" = "Apple"
    "BC:92:6B" = "Apple"; "FC:FC:48" = "Apple"

    # --- Mobile (LG) ---
    "00:05:C9" = "LG"; "00:10:3F" = "LG"; "00:14:80" = "LG"
    "00:19:A1" = "LG"; "00:1C:62" = "LG"; "00:1E:75" = "LG"
    "00:1E:B2" = "LG"; "00:1F:6B" = "LG"; "00:1F:E3" = "LG"
    "00:20:CC" = "LG"; "00:21:3C" = "LG"; "00:22:A9" = "LG"
    "00:23:93" = "LG"; "00:24:21" = "LG"; "00:24:83" = "LG"
    "00:24:AD" = "LG"; "00:25:E5" = "LG"; "00:26:E2" = "LG"
    "34:4D:F7" = "LG"; "34:FC:EF" = "LG"; "38:46:12" = "LG"
    "3C:BD:D8" = "LG"; "40:B0:FA" = "LG"; "44:6D:6C" = "LG"

    # --- Router / Network ---
    "00:11:32" = "Synology"
    "00:E0:4C" = "Realtek"; "00:07:32" = "Realtek"; "52:54:00" = "Realtek"
    "1C:F2:9A" = "EFM Networks (ipTime)"; "88:40:67" = "EFM Networks (ipTime)"; "88:36:6C" = "EFM Networks (ipTime)"
    "00:0D:37" = "D-Link"; "00:13:46" = "D-Link"; "00:15:E9" = "D-Link"
    "00:0C:41" = "Cisco"; "00:13:19" = "Cisco"; "00:14:69" = "Cisco"
    "00:14:BF" = "Cisco"; "60:73:5C" = "Cisco"; "00:22:6B" = "Cisco"
    "00:14:78" = "TP-LINK"; "00:19:E0" = "TP-LINK"; "00:21:91" = "TP-LINK"
    "00:23:CD" = "TP-LINK"; "00:25:86" = "TP-LINK"; "00:27:19" = "TP-LINK"
    "F0:9F:C2" = "Ubiquiti"; "DC:9F:DB" = "Ubiquiti"; "74:83:C2" = "Ubiquiti"
    "00:1A:11" = "Google"; "3C:5A:B4" = "Google"; "F8:8F:CA" = "Google"

    # --- PC / Laptop ---
    "00:0C:F1" = "Intel"; "00:13:20" = "Intel"; "00:15:00" = "Intel"
    "00:1B:77" = "Intel"; "00:21:5C" = "Intel"
    "00:14:A4" = "Hon Hai (Foxconn)"
    "00:1C:25" = "Hon Hai (Foxconn)"
    "00:90:F5" = "Clevo (Hansung etc.)"
    "00:1D:72" = "MSI"

    # --- IoT ---
    "B8:27:EB" = "Raspberry Pi"; "DC:A6:32" = "Raspberry Pi"; "D8:3A:DD" = "Raspberry Pi"
    "2C:3A:E8" = "Espressif (ESP)"; "60:01:94" = "Espressif (ESP)"
    "00:17:88" = "Philips Lighting"
    "44:65:0D" = "Amazon"; "50:F5:DA" = "Amazon"
    
    # --- Additional Findings ---
    "44:D5:CC" = "Amazon"; "08:84:9D" = "Amazon"
    "04:B9:E3" = "Samsung"
    "78:11:DC" = "Xiaomi"; "44:23:7C" = "Xiaomi"; "04:CF:8C" = "Xiaomi"
    "B0:F8:93" = "MXCHIP (IoT)"; "2C:98:11" = "Cloud Network (TP-Link)"
    "70:5D:CC" = "EFM Networks (ipTime)"
}

# --- Load External OUI DB (oui.txt) ---
$OuiFile = Join-Path $PSScriptRoot "oui.txt"
if (Test-Path $OuiFile) {
    Write-Output "Loading Vendor DB from $OuiFile..."
    Get-Content $OuiFile -Encoding UTF8 | ForEach-Object {
        if ($_ -match "^\s*([0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2})\s*=\s*(.+)$") {
            $Prefix = $matches[1].Replace("-", ":").ToUpper()
            $VendorName = $matches[2].Trim()
            
            # Upsert into DB
            $VendorOUI[$Prefix] = $VendorName
        }
    }
}

$ScanScriptBlock = {
    param($IP, $Ports)
    
    function Test-PortInternal {
        param($IP, $Port, $Timeout = 200)
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $Connect = $TcpClient.BeginConnect($IP, $Port, $null, $null)
            $Wait = $Connect.AsyncWaitHandle.WaitOne($Timeout, $false)
            if ($Wait -and $TcpClient.Connected) {
                $TcpClient.EndConnect($Connect)
                return $true
            }
            return $false
        }
        catch { return $false }
        finally { $TcpClient.Dispose() }
    }

    function Get-BannerInternal {
        param($IP, $Port)
        $ExcluedPorts = @(53, 445, 3389)
        if ($Port -in $ExcluedPorts) { return $null }

        $TcpClient = New-Object System.Net.Sockets.TcpClient
        try {
            $Connect = $TcpClient.BeginConnect($IP, $Port, $null, $null)
            if ($Connect.AsyncWaitHandle.WaitOne(300, $false) -and $TcpClient.Connected) {
                $TcpClient.EndConnect($Connect)
                $Stream = $TcpClient.GetStream()
                $Stream.ReadTimeout = 1000 # Increased to 1s
                
                # Probe Selection
                $Probe = "`r`n"
                if ($Port -in @(80, 8080)) {
                    $Probe = "HEAD / HTTP/1.0`r`nUser-Agent: Netscan`r`n`r`n"
                }

                $SendBytes = [System.Text.Encoding]::ASCII.GetBytes($Probe)
                $Stream.Write($SendBytes, 0, $SendBytes.Length)
                
                # Give server a moment
                Start-Sleep -Milliseconds 100
                
                if ($Stream.DataAvailable) {
                    $Buffer = New-Object byte[] 1024
                    $BytesRead = $Stream.Read($Buffer, 0, $Buffer.Length)
                    $RawBanner = [System.Text.Encoding]::ASCII.GetString($Buffer, 0, $BytesRead)
                    
                    # Parse HTTP Server Header
                    if ($RawBanner -match "Server:\s*([^\r\n]+)") {
                        return $matches[1].Trim()
                    }
                    
                    # Generic: First line only
                    $Lines = $RawBanner -split "`r`n"
                    $Banner = $Lines[0] -replace "[^a-zA-Z0-9 ._:-]", " "
                    return $Banner.Trim()
                }
            }
        }
        catch {}
        finally { $TcpClient.Dispose() }
        return $null
    }

    $Result = [PSCustomObject]@{
        IP        = $IP
        IsUp      = $false
        Status    = "Offline"
        Hostname  = ""
        TTL       = $null
        OpenPorts = @()
        Banners   = @()
        OS        = "Unknown"
    }

    # Ping
    try {
        $Ping = New-Object System.Net.NetworkInformation.Ping
        $Reply = $Ping.Send($IP, 750)
        if ($Reply.Status -eq "Success") {
            $Result.IsUp = $true
            $Result.Status = "Online"
            $Result.TTL = $Reply.Options.Ttl
        }
    }
    catch {}

    # Fallback
    if (-not $Result.IsUp) {
        $FallbackPorts = @(80, 445, 135, 22)
        foreach ($FP in $FallbackPorts) {
            if (Test-PortInternal -IP $IP -Port $FP) {
                $Result.IsUp = $true
                $Result.Status = "Online"
                break
            }
        }
    }

    # ... (inside HTML generation block) ...
    [void]$HTMLBuilder.AppendLine("a { text-decoration: none; color: #0078d7; font-weight: bold; }")
    [void]$HTMLBuilder.AppendLine("a:hover { text-decoration: underline; }")
    [void]$HTMLBuilder.AppendLine(".dot { height: 10px; width: 10px; background-color: #bbb; border-radius: 50%; display: inline-block; margin-right: 5px; }")
    [void]$HTMLBuilder.AppendLine(".online { background-color: #28a745; }")
    [void]$HTMLBuilder.AppendLine(".offline { background-color: #bbb; }")
    [void]$HTMLBuilder.AppendLine("</style>")
    [void]$HTMLBuilder.AppendLine("</head><body>")

    # ... (inside loop) ...
    $StatusHTML = "<span class='dot offline'></span>Offline"
    if ($Row.Status -eq "Online") {
        $StatusHTML = "<span class='dot online'></span>Online"
    }

    [void]$HTMLBuilder.AppendLine("<tr>")
    [void]$HTMLBuilder.AppendLine("<td>$($Row.IP)</td><td>$($Row.Hostname)</td><td>$($Row.MAC)</td><td>$($Row.Vendor)</td><td>$StatusHTML</td><td>$($Row.OS)</td><td>$PortsHTML</td><td>$($Row.Banners)</td>")
    [void]$HTMLBuilder.AppendLine("</tr>")

    if ($Result.IsUp) {
        try {
            $HostEntry = [System.Net.Dns]::GetHostEntry($IP)
            $Result.Hostname = $HostEntry.HostName
        }
        catch {}

        # Scan Ports
        if ($Ports) {
            foreach ($P in $Ports) {
                if (Test-PortInternal -IP $IP -Port $P) {
                    $Result.OpenPorts += $P
                    $B = Get-BannerInternal -IP $IP -Port $P
                    if ($B) { $Result.Banners += "$P`:$B" }
                }
            }
        }
        
        # OS Guess
        if ($Result.TTL) {
            if ($Result.TTL -le 64) { $Result.OS = "Linux/Unix/Mac" }
            elseif ($Result.TTL -le 128) { $Result.OS = "Windows" }
            elseif ($Result.TTL -le 255) { $Result.OS = "Network Device" }
        }
    }
    
    return $Result
}

# Runspace Pool
try {
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $Threads)
    $RunspacePool.Open()
}
catch {
    Write-Error "RunspacePool Init Failed: $_"
    exit
}

$Jobs = @()
foreach ($IP in $IPList) {
    $PS = [powershell]::Create()
    $PS.RunspacePool = $RunspacePool
    $PS.AddScript($ScanScriptBlock).AddArgument($IP).AddArgument($Ports) | Out-Null
    $Jobs += New-Object PSObject -Property @{ PS = $PS; Handle = $PS.BeginInvoke() }
}

$Finished = 0
$Results = @()
Write-Output "Scanning..."

while ($Finished -lt $Jobs.Count) {
    foreach ($Job in $Jobs) {
        if ($Job.Handle -and $Job.Handle.IsCompleted) {
            $Obj = $Job.PS.EndInvoke($Job.Handle)
            $Job.Handle = $null
            $Finished++
            
            if ($Obj) {
                $Item = $Obj[0]
                if ($Item.IsUp) {
                    # Add ARP/Vendor info (Main thread)
                    $Mac = $ArpTable[$Item.IP]
                    $Vendor = ""
                    if ($Mac) {
                        $MacClean = $Mac -replace "[:-]", ""
                         
                        # Check Known
                        foreach ($Key in $VendorOUI.Keys) {
                            $CleanKey = $Key -replace "[:-]", ""
                            if ($MacClean.StartsWith($CleanKey)) {
                                $Vendor = $VendorOUI[$Key]; break
                            }
                        }

                        # Check Randomized / Unknown
                        if (-not $Vendor) {
                            $FirstByte = [Convert]::ToByte($MacClean.Substring(0, 2), 16)
                            if (($FirstByte -band 2) -eq 2) {
                                $Vendor = "Randomized (Privacy)"
                            }
                            else {
                                $Vendor = "Unknown ($($MacClean.Substring(0,6)))"
                            }
                        }
                    }
                    
                    # Augment Result
                    $Item | Add-Member -MemberType NoteProperty -Name "MAC" -Value $Mac -Force
                    $Item | Add-Member -MemberType NoteProperty -Name "Vendor" -Value $Vendor -Force
                    $Results += $Item

                    # Real-time Print
                    $OutStr = "Found: $($Item.IP)"
                    if ($Item.Hostname) { $OutStr += " ($($Item.Hostname))" }
                    if ($Mac) { $OutStr += " [$Mac / $Vendor]" }
                    if ($Item.OpenPorts) { $OutStr += " [Ports: $($Item.OpenPorts -join ', ')]" }
                    Write-Output $OutStr
                }
            }
            $Job.PS.Dispose()
        }
    }
    # Simple progress
    $Progress = [math]::Round(($Finished / $Jobs.Count) * 100)
    Write-Progress -Activity "Netscan 1.3" -Status "$Finished / $($Jobs.Count) ($Progress%)" -PercentComplete $Progress
    Start-Sleep -Milliseconds 100
}

$RunspacePool.Close()
$RunspacePool.Dispose()
Write-Progress -Activity "Netscan 1.3" -Completed

Write-Output ""
Write-Output "Scan Complete."

if ($Results.Count -gt 0) {
    Write-Output "--- Summary ---"
    
    # Pre-process results for display/export (Convert Arrays to Strings)
    $FinalResults = $Results | Select-Object IP, Hostname, MAC, Vendor, Status, OS, @{N = 'OpenPorts'; E = { $_.OpenPorts -join ", " } }, @{N = 'Banners'; E = { $_.Banners -join " | " } } | Sort-Object { [Version]$_.IP }
    
    $FinalResults | Format-Table -AutoSize
    
    if ($ExportCSV) {
        try {
            $FinalResults | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
            Write-Output "CSV Saved to $ExportCSV"
        }
        catch { Write-Error "CSV Error: $_" }
    }
    
    if ($ExportHTML) {
        try {
            $HTMLBuilder = New-Object System.Text.StringBuilder
            [void]$HTMLBuilder.AppendLine("<html><head>")
            [void]$HTMLBuilder.AppendLine("<meta charset='utf-8'>")
            [void]$HTMLBuilder.AppendLine("<style>")
            [void]$HTMLBuilder.AppendLine("body { font-family: sans-serif; font-size: 14px; }")
            [void]$HTMLBuilder.AppendLine("h2 { color: #333; }")
            [void]$HTMLBuilder.AppendLine("table { border-collapse: collapse; width: 100%; margin-top: 20px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }")
            [void]$HTMLBuilder.AppendLine("th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }")
            [void]$HTMLBuilder.AppendLine("th { background-color: #0078d7; color: white; }")
            [void]$HTMLBuilder.AppendLine("tr:nth-child(even) { background-color: #f9f9f9; }")
            [void]$HTMLBuilder.AppendLine("tr:hover { background-color: #f1f1f1; }")
            [void]$HTMLBuilder.AppendLine("a { text-decoration: none; color: #0078d7; font-weight: bold; }")
            [void]$HTMLBuilder.AppendLine("a:hover { text-decoration: underline; }")
            [void]$HTMLBuilder.AppendLine(".dot { height: 10px; width: 10px; background-color: #bbb; border-radius: 50%; display: inline-block; margin-right: 5px; }")
            [void]$HTMLBuilder.AppendLine(".online { background-color: #28a745; }")
            [void]$HTMLBuilder.AppendLine(".offline { background-color: #bbb; }")
            [void]$HTMLBuilder.AppendLine("</style>")
            [void]$HTMLBuilder.AppendLine("</head><body>")
            [void]$HTMLBuilder.AppendLine("<h2>Netscan Result</h2>")
            [void]$HTMLBuilder.AppendLine("<p><strong>Target:</strong> $Target | <strong>Time:</strong> $(Get-Date)</p>")
            
            [void]$HTMLBuilder.AppendLine("<table>")
            [void]$HTMLBuilder.AppendLine("<tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Status</th><th>OS</th><th>OpenPorts</th><th>Banners</th></tr>")

            foreach ($Row in $FinalResults) {
                # Format Ports with Links
                $PortLinks = @()
                $PortsArray = $Row.OpenPorts -split ","
                foreach ($P in $PortsArray) {
                    $P = $P.Trim()
                    if ($P) {
                        $Protocol = $null
                        switch ($P) {
                            { $_ -in 80, 8080, 8000, 8008, 8081, 8888 } { $Protocol = "http" }
                            { $_ -in 443, 8443, 9443 } { $Protocol = "https" }
                            21 { $Protocol = "ftp" }
                            22 { $Protocol = "ssh" }
                            23 { $Protocol = "telnet" }
                            3389 { $Protocol = "rdp" }
                        }
                        
                        if ($Protocol) {
                            $LinkTarget = ""
                            if ($Protocol -match "^http") { $LinkTarget = " target='_blank'" }
                            $PortLinks += "<a href='${Protocol}://$($Row.IP):${P}'${LinkTarget}>$P</a>"
                        }
                        else {
                            $PortLinks += $P
                        }
                    }
                }
                $PortsHTML = $PortLinks -join ", "
                
                $StatusHTML = "<span class='dot offline'></span>Offline"
                if ($Row.Status -eq "Online") {
                    $StatusHTML = "<span class='dot online'></span>Online"
                }

                [void]$HTMLBuilder.AppendLine("<tr>")
                [void]$HTMLBuilder.AppendLine("<td>$($Row.IP)</td><td>$($Row.Hostname)</td><td>$($Row.MAC)</td><td>$($Row.Vendor)</td><td>$StatusHTML</td><td>$($Row.OS)</td><td>$PortsHTML</td><td>$($Row.Banners)</td>")
                [void]$HTMLBuilder.AppendLine("</tr>")
            }
            [void]$HTMLBuilder.AppendLine("</table>")
            [void]$HTMLBuilder.AppendLine("</body></html>")
            
            $HTMLBuilder.ToString() | Out-File -FilePath $ExportHTML -Encoding UTF8
            Write-Output "HTML Saved to $ExportHTML"
        }
        catch { Write-Error "HTML Error: $_" }
    }
}
else {
    Write-Output "No active hosts found."
}
