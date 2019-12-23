@echo off
net session 1>NUL 2>NUL || (
    echo This script requires elevated rights. Please run the batch file again as administrator to proceed further.
    pause
    exit
)
:: Setting up variables first.
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
 		reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
 		reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
 		reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
 	)
)
endlocal
"%~dp0SetACL.exe" -on "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn ace -ace "n:SYSTEM;p:read"
"%~dp0SetACL.exe" -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" -ot reg -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" -ot reg -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" -ot reg -actn ace -ace "n:SYSTEM;p:read"
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "2710" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v ForegroundLockTimeout /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d "5000" /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v LinkResolveIgnoreLinkInfo /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveSearch /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoResolveTrack /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoLowDiskSpaceChecks /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d "1000" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v LastAccess /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ExtendedUIHoverTime /t REG_DWORD /d "10000" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotification /t REG_DWORD /d "0" /f
reg add "HKEY_CLASSES_ROOT\CLSID{018D5C66-4533-4307-9B53- 224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCentre /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v IconVerticalSpacing /t REG_SZ /d "-1125" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSecondsInSystemClock /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v DiagnosticErrorText /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v DiagnosticErrorText /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v DiagnosticLinkText /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Games" /v FpsAll /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Games" /v GameFluidity /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Games" /v FpsStatusGames /t REG_DWORD /d "10" /f
reg add "HKCU\SOFTWARE\Microsoft\Games" /v FpsStatusGamesAll /t REG_DWORD /d "4" /f
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v AutoRepeatDelay /t REG_SZ /d "500" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v AutoRepeatRate /t REG_SZ /d "20" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v DelayBeforeAcceptance /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d "27" /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v AccentColor /t REG_DWORD /d "1513239" /f
reg add "HKCU\Software\Microsoft\Windows\DWM" /v AccentColorInactive /t REG_DWORD /d "4473924" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
:: Deleting some Windows and temporary files, they are useless in most cases.
del /q %softdir%\*
for /d %%x in (%softdir%\*) do @rd /s /q ^"%%x^"
if exist %oldwin% (rmdir /s /q %oldwin%)
del /q %temp%\*
for /d %%x in (%temp%\*) do @rd /s /q ^"%%x^"
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
:: Stopping useless and resources-consuming services to make the PC a bit faster since it will have more free general resources.
sc stop "WSearch" & sc config "WSearch" start=disabled
sc stop "wuauserv" & sc config "wuauserv" start=disabled
sc stop "SysMain" & sc config "SysMain" start=disabled
sc stop "BITS" & sc config "BITS" start=disabled
sc stop "MapsBroker" & sc config "MapsBroker" start=disabled
sc stop "DoSvc" & sc config "DoSvc" start=disabled
sc stop "DiagTrack" & sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
:: Disabling useless Windows tasks.
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
:: Setting the default DNS to the cloudflare's one because it's one of the fastest out there.
wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("1.1.1.1", "1.0.0.1")
:: 'Registering' the DNS, in other words this is NOT flushing it. It will refresh the network dns but without flushing it.
ipconfig /registerdns
:: Two bcdedit tweaks, the first one will improve fps by setting the "useplatformclock" value to true. If set to true and your computer supports HPET, it will be used. If it doesn't support it, it won't be used.
:: The second one will increase the free (available) virtual memory by adding as value the amount of RAM in megabytes.
bcdedit /set useplatformclock true
bcdedit /set IncreaseUserVA %mbram%
:: These are unclassified tweaks that will basically improve Windows 10.
powercfg /hibernate off
net user administrator /active:yes
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps" -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps" -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps" -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on "C:\Windows\SystemApps" -ot file -actn ace -ace "n:System;p:read"
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "C:\Windows\SystemApps\%random%"
ren "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" "C:\Windows\SystemApps\%random%"
ren "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe" "C:\Windows\SystemApps\%random%"
ren "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy" "C:\Windows\SystemApps\%random%"
ren "C:\Windows\SystemApps" "C:\Windows\%random%"
:: And finally, we're clearing the event logs from the Microsoft's built-in softwares in Windows 10, this is generally to make the PC faster.
for /F "tokens=*" %%G in ('wevtutil el') DO (call :clearlogs "%%G")
:clearlogs
echo Clearing the log %1
wevtutil cl %1