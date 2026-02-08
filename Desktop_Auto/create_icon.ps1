Add-Type -AssemblyName System.Drawing

$size = 256
$bmp = New-Object System.Drawing.Bitmap $size, $size
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Clear background (transparent)
$g.Clear([System.Drawing.Color]::Transparent)

# Draw Monitor Stand
$brush = [System.Drawing.Brushes]::DarkBlue
$g.FillRectangle($brush, 85, 200, 86, 20)
$g.FillRectangle($brush, 118, 170, 20, 30)

# Draw Monitor Screen Body
$screenRect = New-Object System.Drawing.Rectangle 20, 20, 216, 150
$pen = New-Object System.Drawing.Pen([System.Drawing.Color]::DarkBlue, 10)
$g.DrawRectangle($pen, $screenRect)

# Fill Screen (Blue)
$fillBrush = [System.Drawing.Brushes]::RoyalBlue
$fillRect = New-Object System.Drawing.Rectangle 25, 25, 206, 140
$g.FillRectangle($fillBrush, $fillRect)

# Draw Wireless Waves (White)
$wavePen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 8)
$g.DrawArc($wavePen, 100, 100, 20, 20, -45, 90)
$g.DrawArc($wavePen, 90, 90, 40, 40, -45, 90)
$g.DrawArc($wavePen, 80, 80, 60, 60, -45, 90)


$iconCwd = "C:\Project\Desktop_Auto"
$bmpPath = "$iconCwd\blue_monitor.png"
$icoPath = "$iconCwd\blue_monitor.ico"
$bmp.Save($bmpPath, [System.Drawing.Imaging.ImageFormat]::Png)

# Convert to ICO (simple method: just saving as icon extension works for some APIs, but proper conversion is better)
# PowerShell doesn't have built-in Icon.FromHandle for saving easily without .NET complexity.
# Let's use a simpler approach: System.Drawing.Icon.FromHandle
$hicon = $bmp.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hicon)

$fs = New-Object System.IO.FileStream($icoPath, [System.IO.FileMode]::Create)
$icon.Save($fs)
$fs.Close()

$g.Dispose()
$bmp.Dispose()

Write-Host "Created blue_monitor.ico at $icoPath"
