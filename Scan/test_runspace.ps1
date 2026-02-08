$ScriptBlock = {
    param($IP)
    $Result = "Unknown"
    try {
        $Ping = New-Object System.Net.NetworkInformation.Ping
        $Reply = $Ping.Send($IP, 1000)
        if ($Reply.Status -eq "Success") {
            $Result = "Up"
        }
        else {
            $Result = "Down ($($Reply.Status))"
        }
    }
    catch {
        $Result = "Error: $_"
    }
    return [PSCustomObject]@{ IP = $IP; Status = $Result }
}

$RunspacePool = [runspacefactory]::CreateRunspacePool(1, 2)
$RunspacePool.Open()

$PowerShell = [powershell]::Create()
$PowerShell.RunspacePool = $RunspacePool
$PowerShell.AddScript($ScriptBlock).AddArgument("127.0.0.1") | Out-Null

$Handle = $PowerShell.BeginInvoke()
while (-not $Handle.IsCompleted) { Start-Sleep -Milliseconds 100 }
$Output = $PowerShell.EndInvoke($Handle)

$Output | Format-Table

$RunspacePool.Close()
$RunspacePool.Dispose()
