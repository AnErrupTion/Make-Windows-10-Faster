@echo off
net session 1>NUL 2>NUL || (
    echo This script requires elevated rights. Please run the batch file again as administrator to proceed further.
    pause
    exit
)
:: Setting up variables first.
set loctemp="%temp%"
set wintemp="%windir%\Temp"
set prefetch="%windir%\Prefetch"
set softdir="%windir%\SoftwareDistribution\Download"
set oldwin="%windir%../Windows.old"
set ondir="%USERPROFILE%\OneDrive"
set time=%TIME%
set backup="%cd%\onedriveBackup\"
title Optimize Windows
set /p mtu=Enter your MTU : 
set /p nettype=Are you on Ethernet or Wi-Fi? 
set /p mbram=Enter your amount of RAM in megabytes, example : if you have 4 GB, you will enter 4096 : 
cls
:: Basically we're resetting the network's settings so we can apply our tweaks after.
ipconfig /release
ipconfig /renew
netsh int tcp reset
:: Basic but good netsh tweaks using proper syntax.
netsh int tcp set heuristics disabled
netsh int tcp set global autotuning=disabled
netsh int tcp set global rss=disabled
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set supplemental custom congestionprovider=ctcp
netsh int tcp set global ecncapability=enabled
netsh int tcp set global timestamps=enabled
netsh int tcp set global rsc=disabled
netsh int tcp set global dca=disabled
netsh int tcp set global netdma=disabled
netsh int tcp set global nonsackrttresiliency=enabled
netsh interface ipv4 set subinterface "%nettype%" mtu=%mtu% store=persistent
netsh interface ipv6 set subinterface "%nettype%" mtu=%mtu% store=persistent
:: Some basic and good registry tweaks with proper syntax and also putting the TCP values in the interfaces, not in the parameters.
setlocal EnableDelayedExpansion
set validInterfaces=%regBranch:\0\0=\0%
if /i not "%validInterfaces:~-2%"=="\0" (set validInterfaces=%validInterfaces%\0)
set regbrnch=HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
for /f "tokens=1-8 delims=\" %%i in ( '%Sys32%reg query %regbrnch%' ) do (
	%Sys32%reg query %regbrnch%\%%p /v DhcpIPAddress
 	if !ERRORLEVEL! equ 0 (
 		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
 		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
 		reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
 	)
)
endlocal
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn ace -ace "n:SYSTEM;p:read"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" -ot reg -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" -ot reg -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" -ot reg -actn ace -ace "n:SYSTEM;p:read"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "2710" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ForegroundLockTimeout /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "100" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d "5000" /f
reg add "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Copy To" /v @ /t REG_SZ /d "{C2FBB630-2971-11D1-A18C-00C04FD75D13}" /f
reg add "HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\Move To" /v @ /t REG_SZ /d "{C2FBB631-2971-11D1-A18C-00C04FD75D13}" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d "1000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "8" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d "1000" /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "8" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v LinkResolveIgnoreLinkInfo /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveSearch /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveTrack /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d "1000" /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v LastAccess /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ExtendedUIHoverTime /t REG_DWORD /d "10000" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotification /t REG_DWORD /d "0" /f
reg add "HKEY_CLASSES_ROOT\CLSID{018D5C66-4533-4307-9B53- 224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCentre /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v IconVerticalSpacing /t REG_SZ /d "-1125" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSecondsInSystemClock /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v DiagnosticErrorText /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v DiagnosticErrorText /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v DiagnosticLinkText /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d "1" /f
:: Deleting some Windows and temporary files, they are useless in most cases.
del /q %softdir%\*
for /d %%x in (%softdir%\*) do @rd /s /q ^"%%x^"
if exist %oldwin% (rmdir /s /q %oldwin%)
del /q %prefetch%\*
del /q %loctemp%\*
for /d %%x in (%loctemp%\*) do @rd /s /q ^"%%x^"
del /q %wintemp%\*
for /d %%x in (%wintemp%\*) do @rd /s /q ^"%%x^"
:: Trying to remove OneDrive, it's the most useless thing Microsoft ever created.
if exist %ondir% (
    mkdir %backup%
    xcopy /e /v %ondir% %backup% /y
    rmdir %ondir%
    taskkill /f /im OneDrive.exe
    wmic /node:"hostname" product where name="Microsoft OneDrive" call uninstall /nointeractive
)
:: Killing useless processes such as the updating services from most chromium-based browsers, since when you'll restart your computer they will launch again (you must disable the service to make them not launch again).
taskkill /f /im CryptoTabUpdate.exe
taskkill /f /im CryptoTabCrashHandler64.exe
taskkill /f /im CryptoTabCrashHandler.exe
taskkill /f /im BraveUpdate.exe
taskkill /f /im HTTPDebuggerSvc.exe
taskkill /f /im HTTPDebuggerPro.exe
taskkill /f /im MicrosoftEdgeUpdate.exe
taskkill /f /im ChromeUpdate.exe
taskkill /f /im SearchUI.exe
:: Stopping useless and resources-consuming services to make the PC a bit faster since it will have more free general resources.
net stop "WSearch" & sc config "WSearch" start=disabled
net stop "wuauserv" & sc config "wuauserv" start=disabled
net stop "SysMain" & sc config "SysMain" start=disabled
net stop "Superfetch" & sc config "Superfetch" start=disabled
net stop "TrustedInstaller" & sc config "TrustedInstaller" start=disabled
net stop "HTTPDebuggerPro" & sc config "HTTPDebuggerPro" start=disabled
net stop "BITS" & sc config "BITS" start=disabled
net stop "MapsBroker" & sc config "MapsBroker" start=disabled
net stop "DoSvc" & sc config "DoSvc" start=disabled
net stop "DiagTrack" & sc config "DiagTrack" start=disabled
net stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
:: Setting the default DNS to the cloudflare's one because it's one of the fastest out there.
wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("1.1.1.1", "1.0.0.1")
:: Flushing the DNS, in other words this will clear the network's DNS cache so it will remove outdated things in it. Note that web pages could be slower to load since the cache has been cleared.
ipconfig /flushdns
:: Two bcdedit tweaks, the first one will improve fps by deleting the "useplatformclock" value (why not disabling it only you may ask? Well, if you only disable it and you restart your computer, it will prompt a text where it'll says that it sucessfully disabled that value, which in most cases we don't want.)
:: The second one will increase the free (available) virtual memory by adding as value the amount of RAM in megabytes (i.e. if you have 4GB of RAM, you'll put 4096).
bcdedit /deletevalue useplatformclock
bcdedit /set IncreaseUserVA %mbram%
:: These are unclassified tweaks that will basically improve Windows 10.
powercfg /hibernate off
net user administrator /active:yes
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ot file -actn ace -ace "n:System;p:read"
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUI.bak"
:: And finally, we're clearing the event logs from the Microsoft's built-in softwares in Windows 10, this is generally to make the PC faster.
for /F "tokens=*" %%G in ('wevtutil el') DO (call :clearlogs "%%G")
:clearlogs
echo Clearing the log %1
wevtutil cl %1