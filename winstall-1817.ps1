winget install --id=Microsoft.VisualStudioCode -e  ; winget install --id=7zip.7zip -e  ; winget install --id=WireGuard.WireGuard -e  ; winget install --id=Brave.Brave -e  ; winget install --id=voidtools.Everything -e  ; winget install --id=Flow-Launcher.Flow-Launcher -e  ; winget install --id=JetBrains.PyCharm.Community -e  ; winget install --id=VideoLAN.VLC -e  ; winget install --id=Adobe.Acrobat.Reader.64-bit -e  ; winget install --id=qBittorrent.qBittorrent -e  ; winget install --id=calibre.calibre -e ; winget install --id=Kakao.KakaoTalk  -e ; winget install -e --id Mozilla.Firefox

# Set the TaskbarGlomLevel value to 2 to never combine taskbar buttons
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 2

# Set old context menu
New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Value "" -Force

#Remove all pinned apps from start menu
#Requires -RunAsAdministrator

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$layoutFile="C:\Windows\StartMenuLayout.xml"

#Delete layout file if it already exists
If(Test-Path $layoutFile)
{
    Remove-Item $layoutFile
}

#Creates the blank layout file
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

$regAliases = @("HKLM", "HKCU")

#Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    IF(!(Test-Path -Path $keyPath)) { 
        New-Item -Path $basePath -Name "Explorer"
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}

#Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
Stop-Process -name explorer
Start-Sleep -s 5
$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
Start-Sleep -s 5

#Enable the ability to pin items again by disabling "LockedStartLayout"
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}


Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
Remove-Item $layoutFile




# Restart Explorer to apply the changes
Stop-Process -Name explorer -Force
Start-Process explorer
