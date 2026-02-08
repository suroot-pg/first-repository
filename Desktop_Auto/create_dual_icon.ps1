Add-Type -AssemblyName System.Drawing

$size = 256
$bmp = New-Object System.Drawing.Bitmap $size, $size
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Clear background (transparent)
$g.Clear([System.Drawing.Color]::Transparent)

$darkBlue = [System.Drawing.Color]::FromArgb(0, 0, 139)
$royalBlue = [System.Drawing.Color]::FromArgb(65, 105, 225) # RoyalBlue

# --- Monitor 2 (Background/Right) ---
$brush = New-Object System.Drawing.SolidBrush($darkBlue)
$fillBrush = New-Object System.Drawing.SolidBrush($royalBlue)

# Stand
$g.FillRectangle($brush, 170, 180, 50, 15)
$g.FillRectangle($brush, 190, 150, 10, 30)

# Screen Body
$screenRect2 = New-Object System.Drawing.Rectangle 130, 40, 160, 110
$pen = New-Object System.Drawing.Pen($darkBlue, 8)
$g.DrawRectangle($pen, $screenRect2)

# Screen Fill
$fillRect2 = New-Object System.Drawing.Rectangle 134, 44, 152, 102
$g.FillRectangle($fillBrush, $fillRect2)


# --- Monitor 1 (Foreground/Left) ---
# Stand
$g.FillRectangle($brush, 50, 210, 60, 15)
$g.FillRectangle($brush, 75, 180, 10, 30)

# Screen Body
$screenRect1 = New-Object System.Drawing.Rectangle 10, 70, 180, 120
$g.DrawRectangle($pen, $screenRect1)

# Screen Fill
$fillRect1 = New-Object System.Drawing.Rectangle 14, 74, 172, 112
$g.FillRectangle($fillBrush, $fillRect1)

# Save
$iconCwd = "C:\Project\Desktop_Auto"
$bmpPath = "$iconCwd\blue_dual_monitor.png"
$icoPath = "$iconCwd\blue_dual_monitor.ico"
$bmp.Save($bmpPath, [System.Drawing.Imaging.ImageFormat]::Png)

# Convert to ICO
$hicon = $bmp.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hicon)
$fs = New-Object System.IO.FileStream($icoPath, [System.IO.FileMode]::Create)
$icon.Save($fs)
$fs.Close()

$g.Dispose()
$bmp.Dispose()
Write-Host "Created blue_dual_monitor.ico at $icoPath"
