@echo off
:: Title
Title GSecurity & color 0b

:: Active folder
pushd %~dp0

:: Andrzej Pluta (invisibility)
C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell -NonInteractive -WindowStyle hidden -command Set-MpPreference -EnableNetworkProtection Enabled; Set-MpPreference -EnableControlledFolderAccess Enabled; Set-MpPreference -DisableRealtimeMonitoring 0; Set-MpPreference -DisableBehaviorMonitoring 0; Set-MpPreference -DisableBlockAtFirstSeen 0; Set-MpPreference -MAPSReporting 2; Set-MpPreference -SubmitSamplesConsent 1; Set-MpPreference -DisableIOAVProtection 0; Set-MpPreference -DisableScriptScanning 0; Set-MpPreference -PUAProtection Enabled; Set-MpPreference -ScanAvgCPULoadFactor 50; Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550,D4F940AB-401B-4EFC-AADC-AD5F3C50688A,3B576869-A4EC-4529-8536-B80A7769E899,75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84,D3E037E1-3EB8-44C8-A917-57927947596D,5BEB7EFE-FD9A-4556-801D-275E5FFC04CC,92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B,01443614-cd74-433a-b99e-2ecdc07bfc25,c1db55ab-c21a-4637-bb3f-a12568109d35,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,d1e49aac-8f56-4280-b9ba-993a6d77406c,b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4,26190899-1602-49e8-8b27-eb1d0a1ce869,7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c,e6db77e5-3df2-4cf1-b95a-636979351e5b,56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled; Add-MpPreference -AttackSurfaceReductionOnlyExclusions $env:SystemRoot'\assembly'; Add-MpPreference -AttackSurfaceReductionOnlyExclusions $env:SystemRoot'\Microsoft.NET\Framework\*\NativeImages'; Add-MpPreference -AttackSurfaceReductionOnlyExclusions $env:SystemRoot'\WinSxS\*\*.ni.dll'; Add-MpPreference -AttackSurfaceReductionOnlyExclusions $env:ProgramData'\Microsoft\Windows Defender';

:: Msg
mshta.exe vbscript:Execute("MsgBox ""Installing GSecurity"", vbOkOnly, ""GSecurity""")(window.close) 

:: Registry
Reg import GSecurity.reg

:: Antilogger
copy /y keycrypt64.sys C:\Windows\system32\drivers\
copy /y keycrypt32.dll C:\Windows\system32\
copy /y keycrypt64.dll C:\Windows\syswow64\
Antilogger.exe /DLL32PATH:"C:\Windows\system32\KeyCrypt32.dll" /DLL64PATH:"C:\Windows\syswow64\KeyCrypt64.dll" /SDKPATH:"C:\Windows\system32"

:: RAM Cleaner
copy /y EmptyStandbyList.exe %systemdrive%\users\Public\
copy /y Ram.bat %systemdrive%\users\Public\
schtasks /create /xml "Ram Cleaner.xml" /tn "Ram Cleaner" /ru ""

:: Security policy
lgpo /s GSecurity.inf

:: Perms
c:
cd\
icacls c: /remove "Authenticated Users"
takeown /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r
icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /inheritance:e /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Active folder
pushd %~dp0

:: Disable remote access
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Disable-PSRemoting -Force"

:: Reset firewall
cls
echo == resetting firewall
Reg delete HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy /f

:: Reset persistent routes
cls
echo == resetting persistent routes
route -f

:: Reset network
cls
echo == resetting network
:: Network Connection Status Indicator (NCSI) - HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet
reg add "HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "1" /f

reg add "HKLM\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f

sc config Dhcp start= auto
sc config DPS start= auto
sc config lmhosts start= auto
sc config NlaSvc start= auto
sc config nsi start= auto
sc config RmSvc start= auto
sc config Wcmsvc start= auto
sc config WdiServiceHost start= demand
sc config Winmgmt start= auto

sc config NcbService start= demand
sc config ndu start= demand
sc config Netman start= demand
sc config netprofm start= demand
sc config WlanSvc start= auto
sc config WwanSvc start= demand

net start DPS
net start nsi
net start NlaSvc
net start Dhcp
net start Wcmsvc
net start RmSvc

schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Enable

:: Disable adapter with index number 0-5 (most likely all), equals to ipconfig /release
wmic path win32_networkadapter where index=0 call disable
wmic path win32_networkadapter where index=1 call disable
wmic path win32_networkadapter where index=2 call disable
wmic path win32_networkadapter where index=3 call disable
wmic path win32_networkadapter where index=4 call disable
wmic path win32_networkadapter where index=5 call disable

:: Timeout to let the network adapter recover
timeout 5

:: Enable adapter with index number 0-5 (most likely all), equals to ipconfig /renew
wmic path win32_networkadapter where index=0 call enable
wmic path win32_networkadapter where index=1 call enable
wmic path win32_networkadapter where index=2 call enable
wmic path win32_networkadapter where index=3 call enable
wmic path win32_networkadapter where index=4 call enable
wmic path win32_networkadapter where index=5 call enable

arp -d *
route -f
nbtstat -R
nbtstat -RR
netsh advfirewall reset

netcfg -d
netsh winsock reset
netsh int 6to4 reset all
netsh int httpstunnel reset all
netsh int ip reset
netsh int isatap reset all
netsh int portproxy reset all
netsh int tcp reset all
netsh int teredo reset all
netsh branchcache reset
ipconfig /release
ipconfig /renew

:: Reset group policy
cls
echo == resetting group policy
rd /s /q "%windir%\system32\Group Policy"
rd /s /q "%windir%\system32\Group Policy Users"
rd /s /q "%windir%\syswow64\Group Policy"
rd /s /q "%windir%\syswow64\Group Policy Users"
Reg.exe delete "HKLM\SOFTWARE\Policies" /f
Reg.exe delete "HKCU\SOFTWARE\Policies" /f

:: Provisioning
rd /s /q %ProgramData%\Microsoft\Provisioning
@powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Uninstall-ProvisioningPackage -AllInstalledPackages"

:: Debloat
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "remove-default-apps.ps1"

:: Hosts
(
echo 127.0.0.1 localhost
echo 127.0.0.1 localhost.localdomain
echo 127.0.0.1 local
echo 255.255.255.255 broadcasthost
echo ::1 localhost
echo ::1 ip6-localhost
echo ::1 ip6-loopback
echo fe80::1%lo0 localhost
echo ff00::0 ip6-localnet
echo ff00::0 ip6-mcastprefix
echo ff02::1 ip6-allnodes
echo ff02::2 ip6-allrouters
echo ff02::3 ip6-allhosts
echo 0.0.0.0 0.0.0.0
)>"%systemdrive%\Windows\System32\Drivers\Etc\hosts"

:: Disable point of entry for Spectre and Meltdown
Dism /Online /Disable-Feature /All /Quiet /NoRestart /FeatureName:"SMB1Protocol"
Dism /Online /Disable-Feature /All /Quiet /NoRestart /FeatureName:"SMB1Protocol-Client"
Dism /Online /Disable-Feature /All /Quiet /NoRestart /FeatureName:"SMB1Protocol-Server"

:: Pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True

:: Boot settings
bcdedit /deletevalue {current} safeboot
bcdedit /deletevalue {current} safebootalternateshell
bcdedit /deletevalue {current} removememory
bcdedit /deletevalue {current} truncatememory
bcdedit /deletevalue {current} useplatformclock
bcdedit /deletevalue {current} disabledynamictick
bcdedit /deletevalue {default} safeboot
bcdedit /deletevalue {default} safebootalternateshell
bcdedit /deletevalue {default} removememory
bcdedit /deletevalue {default} truncatememory
bcdedit /deletevalue {default} useplatformclock
bcdedit /deletevalue {default} disabledynamictick
bcdedit /set {current} hypervisorlaunchtype off
Bcdedit /set {current} flightsigning off
bcdedit /set {current} bootems no
bcdedit /set {current} nx OptOut
bcdedit /set {current} bootux disabled
bcdedit /set {current} bootmenupolicy legacy
bcdedit /set {current} tscsyncpolicy Enhanced
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
bcdedit /set {current} recoveryenabled no
bcdedit /set {current} quietboot yes
bcdedit /set {current} useplatformtick yes
bcdedit /set {current} vsmlaunchtype Off
bcdedit /set {current} vm No
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {globalsettings} custom:16000068 true
bootsect /nt60 sys /force

:: One time cleaner
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "IconStreams" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify" /v "PastIconsStream" /f
fsutil usn deletejournal /d /n c:
ipconfig /flushdns
taskkill /im msi.exe /f
taskkill /im wuauclt.exe /f
taskkill /im sihclient.exe /f
taskkill /im TiWorker.exe /f
taskkill /im trustedinstaller.exe /f
taskkill /im MoUsoCoreWorker.exe /f
taskkill /im UsoClient.exe /f
taskkill /im usocoreworker.exe /f
net stop bits /y
net stop cryptSvc /y
net stop DoSvc /y
net stop EventLog /y
net stop msiserver /y
net stop UsoSvc /y
net stop winmgmt /y
winmgmt /salvagerepository
net stop wuauserv /y
schtasks /End /TN "\Microsoft\Windows\Wininet\CacheTask"

takeown /f "%WINDIR%\winsxs\pending.xml" /a
icacls "%WINDIR%\winsxs\pending.xml" /grant:r Administrators:F /c
del "%WINDIR%\winsxs\pending.xml" /s /f /q

del "A:\$Recycle.bin" /s /f /q
del "B:\$Recycle.bin" /s /f /q
del "C:\$Recycle.bin" /s /f /q
del "D:\$Recycle.bin" /s /f /q
del "E:\$Recycle.bin" /s /f /q
del "F:\$Recycle.bin" /s /f /q
del "G:\$Recycle.bin" /s /f /q
del "H:\$Recycle.bin" /s /f /q
del "I:\$Recycle.bin" /s /f /q
del "J:\$Recycle.bin" /s /f /q
del "K:\$Recycle.bin" /s /f /q
del "L:\$Recycle.bin" /s /f /q
del "M:\$Recycle.bin" /s /f /q
del "N:\$Recycle.bin" /s /f /q
del "O:\$Recycle.bin" /s /f /q
del "P:\$Recycle.bin" /s /f /q
del "Q:\$Recycle.bin" /s /f /q
del "R:\$Recycle.bin" /s /f /q
del "S:\$Recycle.bin" /s /f /q
del "T:\$Recycle.bin" /s /f /q
del "U:\$Recycle.bin" /s /f /q
del "V:\$Recycle.bin" /s /f /q
del "W:\$Recycle.bin" /s /f /q
del "X:\$Recycle.bin" /s /f /q
del "Y:\$Recycle.bin" /s /f /q
del "Z:\$Recycle.bin" /s /f /q
del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat" /s /f /q
del "%LocalAppData%\Microsoft\Windows\WebCache" /s /f /q
del "%LocalAppData%\Temp" /s /f /q
del "%ProgramData%\USOPrivate\UpdateStore" /s /f /q
del "%ProgramData%\USOShared\Logs" /s /f /q
rd "%SystemDrive%\$GetCurrent" /s /q
rd "%SystemDrive%\$SysReset" /s /q
rd "%SystemDrive%\$Windows.~BT" /s /q
rd "%SystemDrive%\$Windows.~WS" /s /q
rd "%SystemDrive%\$WinREAgent" /s /q
rd "%SystemDrive%\OneDriveTemp" /s /q
rd "%SystemDrive%\Recovery" /s /q
del "%temp%" /s /f /q
del "%WINDIR%\Logs" /s /f /q
del "%WINDIR%\Installer\$PatchCache$" /s /f /q
del "%WINDIR%\SoftwareDistribution\Download" /s /f /q
del "%WINDIR%\System32\LogFiles" /s /f /q
del "%WINDIR%\System32\winevt\Logs" /s /f /q
del "%WINDIR%\Temp" /s /f /q
del "%WINDIR%\WinSxS\Backup" /s /f /q

vssadmin delete shadows /for=c: /all /quiet

rem https://forums.mydigitallife.net/threads/windows-10-hotfix-repository.57050/page-622#post-1655591
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "CBSLogCompress" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableComponentBackups" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableResetbase" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "NumCBSPersistLogs" /t "REG_DWORD" /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "SupersededActions" /t "REG_DWORD" /d "3" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "TransientManifestCache" /t "REG_DWORD" /d "1" /f

Dism /get-mountedwiminfo
Dism /cleanup-mountpoints
Dism /cleanup-wim

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Content Indexer Cleaner" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Device Driver Packages" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder" /v "StateFlags65535" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files" /v "StateFlags65535" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v "Autorun" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v "StateFlags65535" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files" /v "StateFlags65535" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files" /v "StateFlags65535" /t REG_DWORD /d "2" /f

:: DHT
"C:\Windows\system32\REG" DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f
"C:\Windows\system32\REG" DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v SavedLegacySettings /f
"C:\Windows\system32\REG" DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f
"C:\Windows\system32\REG" DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /f
"C:\Windows\system32\REG" DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v DefaultConnectionSettings /f
"C:\Windows\system32\REG" DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxySettingsPerUser /f
"C:\Windows\system32\reg" delete HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local /f
"C:\Windows\system32\reg" add HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local /f
"C:\Windows\system32\bitsadmin" /reset /allusers
"C:\Windows\system32\reg" delete "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /f /reg:32
"C:\Windows\system32\reg" delete "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer" /f /reg:64
"C:\Windows\system32\reg" delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
"C:\Windows\system32\reg" add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
"C:\Windows\system32\reg" delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
"C:\Windows\system32\reg" add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
"C:\Windows\system32\reg" delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
"C:\Windows\system32\reg" add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
"C:\Windows\system32\reg" add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v DisableConfig /t REG_DWORD /d 0 /f
"C:\Windows\system32\reg" add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 0 /f
"C:\Windows\system32\reg" delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /f
"C:\Windows\system32\reg" add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend /f /v Start /t REG_DWORD /d 0x00000002
"C:\Windows\system32\reg" add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /f /v DisableAntiSpyware /t REG_DWORD /d 0x00000000
"C:\Windows\system32\reg" add "HKLM\SYSTEM\CurrentControlSet\services\MpsSvc" /V Start /T REG_DWORD /D 2 /F
"C:\Windows\system32\reg" add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /f /v EnableFirewall /t REG_DWORD /d 0x00000001
"C:\Windows\system32\reg" delete "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /f /v DoNotAllowExceptions
"C:\Windows\system32\reg" add "HKLM\SYSTEM\CurrentControlSet\services\wuauserv" /V Start /T REG_DWORD /D 2 /F
"C:\Windows\system32\reg" delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /f /v NoWindowsUpdate
"C:\Windows\system32\reg" add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
"C:\Windows\system32\reg" add "HKLM\SYSTEM\CurrentControlSet\services\wscsvc" /V Start /T REG_DWORD /D 2 /F
"C:\Windows\system32\reg" add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v HideSCAHealth /t REG_SZ /d 0
"C:\Windows\system32\reg" add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f /v HideSCAHealth /t REG_SZ /d 0

:: Prclaunchky
echo == prclaunchky
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t "REG_DWORD" /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t "REG_DWORD" /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t "REG_DWORD" /d "3" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t "REG_SZ" /d "Deny" /f
bcdedit /set "disabledynamictick" "Yes"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGazeInput" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" /v "Value" /t "REG_SZ" /d "Deny" /f
powercfg /H off
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t "REG_DWORD" /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "EnableBackupForWin8Apps" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t "REG_SZ" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t "REG_DWORD" /d "0" /f
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t "REG_DWORD" /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t "REG_DWORD" /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\Classes\.jpg" /ve /t "REG_SZ" /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.jpeg" /ve /t "REG_SZ" /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.gif" /ve /t "REG_SZ" /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.png" /ve /t "REG_SZ" /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.bmp" /ve /t "REG_SZ" /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.tiff" /ve /t "REG_SZ" /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKCU\Software\Classes\.ico" /ve /t "REG_SZ" /d "PhotoViewer.FileAssoc.Tiff" /f
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t "REG_DWORD" /d "1" /f
:: ::::::::::::::::::::::::::::::
:: Sean Rhone (Espionage724)
:: Last updated: 2018/04/15
:: 
:: Removes or disables unnecessary services
:: 
:: Service Display/Nice Name
:: Service Name
:: Service Delete or Disable Command
:: ::::::::::::::::::::::::::::::

:: AMD External Events Utility
:: AMD External Events Utility
sc delete "AMD External Events Utility"

:: AMD FUEL Service
:: AMD FUEL Service
sc delete "AMD FUEL Service"

:: ActiveX Installer (AxInstSV)
:: AxInstSV
sc delete "AxInstSV"

:: AllJoyn Router Service
:: AJRouter
sc delete "AJRouter"

:: AppX Deployment Service (AppXSVC)
:: AppXSvc
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t "REG_DWORD" /d "4" /f

:: BitLocker Drive Encryption Service
:: BDESVC
sc config "BDESVC" start= "disabled"

:: Block Level Backup Engine Service
:: wbengine
sc delete "wbengine"

:: CDPUserSvc
:: CDPUserSvc
sc delete "CDPUserSvc"

:: Data Sharing Service
:: DsSvc
sc delete "DsSvc"

:: Connected User Experiences and Telemetry
:: DiagTrack
sc delete "DiagTrack"

:: Contact Data
:: PimIndexMaintenanceSvc
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t "REG_DWORD" /d "4" /f

:: DataCollectionPublishingService
:: DcpSvc
sc delete "DcpSvc"

:: Diagnostic Policy Service
:: DPS
sc config "DPS" start= "disabled"

:: Diagnostic Service Host
:: WdiServiceHost
sc config "WdiServiceHost" start= "disabled"

:: Diagnostic System Host
:: WdiSystemHost
sc config "WdiSystemHost" start= "disabled"

:: Distributed Link Tracking Client
:: TrkWks
sc delete "TrkWks"

:: dmwappushsvc
:: dmwappushservice
sc delete "dmwappushservice"

:: Downloaded Maps Manager
:: MapsBroker
sc delete "MapsBroker"

:: Encrypting File System (EFS)
:: EFS
sc config "EFS" start= "disabled"

:: File History Service
:: fhsvc
sc delete "fhsvc"

:: Geolocation Service
:: lfsvc
sc delete "lfsvc"

:: HomeGroup Listener
:: HomeGroupListener
sc delete "HomeGroupListener"

:: HomeGroup Provider
:: HomeGroupProvider
sc delete "HomeGroupProvider"

:: MessagingService
:: MessagingService
sc delete "MessagingService"

:: Network Connection Broker
:: NcbService
sc delete "NcbService"

:: Offline Files
:: CscService
sc delete "CscService"

:: Phone Service
:: PhoneSvc
sc delete "PhoneSvc"

:: Problem Reports and Solutions Control Panel Support
:: wercplsupport
sc delete "wercplsupport"

:: Program Compatibility Assistant Service
:: PcaSvc
sc delete "PcaSvc"

:: Remote Desktop Configuration
:: SessionEnv
sc delete "SessionEnv"

:: Remote Desktop Services
:: TermService
sc delete "TermService"

:: Remote Desktop Services UserMode Port Redirector
:: UmRdpService
sc delete "UmRdpService"

:: Remote Registry
:: RemoteRegistry
sc delete "RemoteRegistry"

:: Retail Demo Service
:: RetailDemo
sc delete "RetailDemo"

:: Routing and Remote Access
:: RemoteAccess
sc delete "RemoteAccess"

:: Security Center
:: wscsvc
sc delete "wscsvc"

:: Sync Host
:: OneSyncSvc
sc delete "OneSyncSvc"

:: TCP/IP NetBIOS Helper
:: lmhosts
sc delete "lmhosts"

:: Prevents Start Menu from loading; may be fixable with 3rd-party Start Menu
:: Tile Data model server
:: tiledatamodelsvc
:: reg add "HKLM\SYSTEM\CurrentControlSet\Services\tiledatamodelsvc" /v "Start" /t "REG_DWORD" /d "4" /f

:: Touch Keyboard and Handwriting Panel Service
:: TabletInputService
sc delete "TabletInputService"

:: User Data Access
:: UserDataSvc
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t "REG_DWORD" /d "4" /f

:: User Data Storage
:: UnistoreSvc
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t "REG_DWORD" /d "4" /f

:: User Experience Virtualization Service
:: UevAgentService
sc delete "UevAgentService"

:: VIA Karaoke digital mixer Service
:: VIAKaraokeService
sc delete "VIAKaraokeService"

:: Volume Shadow Copy
:: VSS
sc delete "VSS"

:: Windows Backup
:: SDRSVC
sc delete "SDRSVC"

:: Windows Defender Advanced Threat Protection Service
:: Sense
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t "REG_DWORD" /d "4" /f

:: Windows Defender Network Inspection Service
:: WdNisSvc
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t "REG_DWORD" /d "4" /f

:: Windows Defender Service
:: WinDefend
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t "REG_DWORD" /d "4" /f

:: Windows Error Reporting Service
:: WerSvc
sc delete "WerSvc"

:: Windows Insider Service
:: wisvc
sc delete "wisvc"

:: Windows License Manager Service
:: LicenseManager
sc delete "LicenseManager"

:: Windows Mobile Hotspot Service
:: icssvc
sc delete "icssvc"

:: Windows Push Notifications System Service
:: WpnService
sc delete "WpnService"

:: Windows Remote Management (WS-Management)
:: WinRM
sc delete "WinRM"

:: Windows Search
:: WSearch
sc delete "WSearch"

:: WinHTTP Web Proxy Auto-Discovery Service
:: WinHttpAutoProxySvc
sc delete "WinHttpAutoProxySvc"

:: Workstation
:: LanmanWorkstation
sc delete "LanmanWorkstation"

:: Xbox Live Auth Manager
:: XblAuthManager
sc delete "XblAuthManager"

:: Xbox Live Game Save
:: XblGameSave
sc delete "XblGameSave"

:: Xbox Live Networking Service
:: XboxNetApiSvc
sc delete "XboxNetApiSvc"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t "REG_DWORD" /d "1" /f
:: Initial
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceIDs" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceIDsRetroactive" /t "REG_DWORD" /d "0" /f

:: Intel(R) HD Graphics 530
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" /v "1" /t "REG_SZ" /d "PCI\VEN_8086&DEV_191B&SUBSYS_105B1025&REV_06" /f

:: NVIDIA GeForce GTX 970M
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" /v "2" /t "REG_SZ" /d "PCI\VEN_10DE&DEV_13D8&SUBSYS_105B1025&REV_A1" /f

:: Realtek High Definition Audio
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" /v "3" /t "REG_SZ" /d "HDAUDIO\FUNC_01&VEN_10EC&DEV_0255&SUBSYS_1025105B&REV_1000" /f

::Lift Restrictions
::reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" /v "1" /f
::reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" /v "2" /f
::reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" /v "3" /f
ipconfig /flushdns
reg add "HKLM\SYSTEM\CurrentControlSet\services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\Dnscache\Parameters" /v "MaxCacheTtl" /t "REG_DWORD" /d "1" /f
:: ::::::::::::::::::::::::::::::
:: Sean Rhone (Espionage724)
:: Last updated: 2018/04/15
:: 
:: Removes unnecessary tasks
:: 
:: Task Name
:: Task Description (if present)
:: Task Delete Command
:: ::::::::::::::::::::::::::::::


:: AnalyzeSystem
:: This task analyzes the system looking for conditions that may cause high energy use.
schtasks /Delete /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /F

:: RegIdleBackup
:: Registry Idle Backup Task
schtasks /Delete /TN "Microsoft\Windows\Registry\RegIdleBackup" /F

:: RemoteAssistanceTask
:: Checks group policy for changes relevant to Remote Assistance
schtasks /Delete /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /F

:: CleanupOfflineContent
:: Auto cleanup RetailDemo Offline content
schtasks /Delete /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /F

:: BackgroundUploadTask
:: 
schtasks /Delete /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /F

:: BackupTask
:: 
schtasks /Delete /TN "Microsoft\Windows\SettingSync\BackupTask" /F

:: NetworkStateChangeTask
:: 
schtasks /Delete /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /F

:: NetworkStateDeleteTask
:: 
schtasks /Delete /TN "Microsoft\Windows\SettingSync\NetworkStateDeleteTask" /F

:: SetupCleanupTask
:: Deletes previous Windows installation files a few days after installation.
schtasks /Delete /TN "Microsoft\Windows\Setup\SetupCleanupTask" /F

:: FamilySafetyMonitor
:: Initializes Family Safety monitoring and enforcement.
schtasks /Delete /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /F

:: FamilySafetyMonitorToastTask
:: Synchronizes the latest settings with the Microsoft family features service.
schtasks /Delete /TN "Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /F

:: FamilySafetyRefreshTask
:: Synchronizes the latest settings with the Microsoft family features service.
schtasks /Delete /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /F

:: SpaceAgentTask
:: Storage Spaces Settings
schtasks /Delete /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /F

:: SpaceManagerTask
:: $(@%SystemRoot%\system32\spaceman.exe,-3)
schtasks /Delete /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /F

:: SpeechModelDownloadTask
:: 
schtasks /Delete /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /F

:: Storage Tiers Management Initialization
:: Initializes the Storage Tiers Management service when the first tiered storage space is detected on the system. Do not remove or modify this task.
schtasks /Delete /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /F

:: Storage Tiers Optimization
:: Optimizes the placement of data in storage tiers on all tiered storage spaces in the system.
schtasks /Delete /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Optimization" /F

:: SR
:: This task creates regular system protection points.
schtasks /Delete /TN "Microsoft\Windows\SystemRestore\SR" /F

:: HiveUploadTask
:: This task will automatically upload a roaming user profile's registry hive to its network location.
schtasks /Delete /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /F

:: ResolutionHost
:: The Windows Diagnostic Infrastructure Resolution host enables interactive resolutions for system problems detected by the Diagnostic Policy Service. It is triggered when necessary by the Diagnostic Policy Service in the appropriate user session. If the Diagnostic Policy Service is not running, the task will not run
schtasks /Delete /TN "Microsoft\Windows\WDI\ResolutionHost" /F

:: Windows Defender Cache Maintenance
:: Periodic maintenance task.
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /F

:: Windows Defender Cleanup
:: Periodic cleanup task.
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /F

:: Windows Defender Scheduled Scan
:: Periodic scan task.
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /F

:: Windows Defender Verification
:: Periodic verification task.
schtasks /Delete /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /F

:: QueueReporting
:: Windows Error Reporting task to process queued reports.
schtasks /Delete /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /F

:: Automatic App Update
:: Automatically updates the user's Windows store applications.
schtasks /Delete /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /F

:: XblGameSaveTask
:: XblGameSave Standby Task
schtasks /Delete /TN "Microsoft\XblGameSave\XblGameSaveTask" /F

:: XblGameSaveTaskLogon
:: XblGameSave Logon Task
schtasks /Delete /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /F
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t "REG_DWORD" /d "100" /f
@echo off
net user administrator /active:yes

echo.
echo "Removing Remote Desktop"
echo.

sc delete SessionEnv
sc stop SessionEnv

sc delete TermService
sc stop TermService

sc delete UmRdpService
sc stop UmRdpService

echo.
echo "Removing Remote Registry"
echo.

sc delete RemoteRegistry
sc stop RemoteRegistry

echo.
echo "Removing Connection Manager"
echo.

sc delete Rasman
sc stop Rasman


echo.
echo "Removing Automatic Connection Manager"
echo.

sc delete RasAuto
sc delete RmSvc

echo.
echo ".. Taking Ownership of RDConnection and deleting its driver so service will uninstall"
echo.

takeown /f C:\Windows\System32\termsrv.dll
cacls termsrv.dll /E /P %username%:F
del C:\Windows\System32\termsrv.dll

echo.
echo ".. Taking Ownership of RDManager and deleting its driver so service will uninstall"
echo.

takeown /f C:\Windows\System32\termmgr.dll
cacls termmgr.dll /E /P %username%:F
del C:\Windows\System32\termmgr.dll

echo.
echo "Deleting Connected Devices Platform Service"
sc delete CDPSvc
sc stop CDPSvc

echo.
echo "Deleting Connected Devices Platform User Service"
sc delete CDPUserSvc
sc stop CDPUsersvc

echo.
echo "Deleting Connected User Experiences and Telemetry"
sc delete DiagTrack
sc stop DiagTrack

echo.
echo "Deleting Contact Service"
sc delete PimIndexMaintenanceSvc
sc stop PimIndexMaintenanceSvc

echo.
echo "Disabling Diagnostic Services, Deleting it is Impossibuhhhh"
sc config DPS start= disabled
sc stop DPS

echo.
sc config WdiServiceHost start= disabled
sc stop WdiServiceHost

echo.
sc config WdiSystemHost start= disabled
sc stop WdiSystemHost
echo.

:: Exit
mshta.exe vbscript:Execute("MsgBox ""GSecurity Installation Completed, System Will Restart"", vbOkOnly, ""GSecurity""")(window.close) 
shutdown /r /t 0