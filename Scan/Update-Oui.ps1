$SourceUrl = "https://raw.githubusercontent.com/royhills/arp-scan/master/ieee-oui.txt"
$OutFile = Join-Path $PSScriptRoot "oui.txt"
$TempFile = Join-Path $PSScriptRoot "oui_raw.txt"

Write-Output "Downloading OUI database from royhills/arp-scan ($SourceUrl)..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $SourceUrl -OutFile $TempFile -UseBasicParsing
}
catch {
    Write-Error "Download Failed: $_"
    exit
}

Write-Output "Parsing and optimizing database..."
$OUIList = @{}
$Count = 0

Get-Content $TempFile | ForEach-Object {
    # Format: 000393	Apple Computer, Inc.
    if ($_ -match "^([0-9A-Fa-f]{6})\s+(.+)$") {
        $RawPrefix = $matches[1]
        # Format to XX-XX-XX
        $Prefix = "$($RawPrefix.Substring(0,2))-$($RawPrefix.Substring(2,2))-$($RawPrefix.Substring(4,2))"
        $Vendor = $matches[2].Trim()
        
        if (-not $OUIList.ContainsKey($Prefix)) {
            $OUIList[$Prefix] = $Vendor
            $Count++
        }
    }
}

Write-Output "Saving $Count entries to $OutFile..."
$SortedContent = $OUIList.GetEnumerator() | Sort-Object Name | ForEach-Object {
    "$($_.Name)=$($_.Value)"
}

$SortedContent | Set-Content -Path $OutFile -Encoding UTF8
Remove-Item $TempFile
Write-Output "Done! Netscan will now recognize $Count vendors."
