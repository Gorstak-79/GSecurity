@echo off
:: Title
Title GSecurity & color 0b

:: Active folder
pushd %~dp0

:: Antilogger
copy /y keycrypt64.sys C:\Windows\system32\drivers\
copy /y keycrypt32.dll C:\Windows\system32\
copy /y keycrypt64.dll C:\Windows\syswow64\
Antilogger.exe /DLL32PATH:"C:\Windows\system32\KeyCrypt32.dll" /DLL64PATH:"C:\Windows\syswow64\KeyCrypt64.dll" /SDKPATH:"C:\Windows\system32"

:: RAM Cleaner
copy /y EmptyStandbyList.exe %systemdrive%\users\Public\
copy /y Ram.bat %systemdrive%\users\Public\
schtasks /create /xml "Ram Cleaner.xml" /tn "Ram Cleaner" /ru ""

:: Registry
Reg import GSecurity.reg

:: 3rd party scripts
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Age of Empires II Definitive Edition.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0AMD Graphics.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0American Truck Simulator.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ApplicationFrameHost.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0audiodg.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Beat Saber.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Blade & Sorcery.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0City Car Driving.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0csrss.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dasHost.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diablo II Resurrected.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diablo Immortal.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dllhost.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Dota 2.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dwm.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0explorer.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Grand Theft Auto V.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Guild Wars 2.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Half-Life Alyx.ps1
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Horizon Zero Dawn.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LatencyMon.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0lsass.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ntoskrnl.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Oculus.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Project CARS 3.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SecurityHealthService.ps1
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0services.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SgrmBroker.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sihost.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Skyrim VR.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0STAR WARS Squadrons.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SteamVR.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0svchost.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WMIADAP.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WmiPrvSE.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Zenith The Last City.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0remove-default-apps.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-scheduled-tasks.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-memory-compression.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-prefetch-prelaunch.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0optimize-windows-update.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0optimize-user-interface.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fix-privacy-settings.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0experimental_unfuckery.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0disable-services.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0block-telemetry.ps1"
@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Win10.ps1" -include "%~dp0Win10.psm1" -preset "%~dpn0.preset"

:: Exit
Exit