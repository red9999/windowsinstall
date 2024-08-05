winget install --id=Microsoft.VisualStudioCode -e  ; winget install --id=7zip.7zip -e  ; winget install --id=WireGuard.WireGuard -e  ; winget install --id=Brave.Brave -e  ; winget install --id=voidtools.Everything -e  ; winget install --id=Flow-Launcher.Flow-Launcher -e  ; winget install --id=JetBrains.PyCharm.Community -e  ; winget install --id=VideoLAN.VLC -e  ; winget install --id=Adobe.Acrobat.Reader.64-bit -e  ; winget install --id=qBittorrent.qBittorrent -e  ; winget install --id=calibre.calibre -e ; winget install --id=Kakao.KakaoTalk  -e ; winget install -e --id Mozilla.Firefox ; winget install -e --id calibre.calibre

# Set the TaskbarGlomLevel value to 2 to never combine taskbar buttons
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 2

# Restart Explorer to apply the changes
Stop-Process -Name explorer -Force
Start-Process explorer
