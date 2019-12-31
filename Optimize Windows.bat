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
title [Optimize Windows v1.4 by AnErrupTion, with the help of internet]
set /p mtu=Enter your MTU : 
set /p nettype=Are you on Ethernet or Wi-Fi? 
set /p mbram=Enter your amount of RAM in megabytes, example : if you have 4 GB, you will enter 4096 : 
cls
:: Basically we're resetting the network's settings so we can apply our tweaks after.
ipconfig /release
ipconfig /renew
netsh int tcp reset
:: Basic but good netsh tweaks using proper syntax.
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rsc=disabled
netsh int tcp set global rss=enabled
netsh int tcp set global autotuning=disabled
netsh int tcp set heuristics disabled
netsh int tcp set supplemental custom congestionprovider=cubic
netsh int tcp set supplemental internet congestionprovider=cubic
netsh int tcp set global dca=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global initialrto=2500
netsh int ipv4 set global defaultcurhoplimit=255
netsh int ipv6 set global defaultcurhoplimit=255
netsh int ipv4 set subinterface "%nettype%" mtu=%mtu% store=persistent
netsh int ipv6 set subinterface "%nettype%" mtu=%mtu% store=persistent
:: Stopping useless and resources-consuming services to make the PC a bit faster since it will have more free general resources.
sc stop "WSearch" & sc config "WSearch" start=disabled
sc stop "wuauserv" & sc config "wuauserv" start=disabled
sc stop "SysMain" & sc config "SysMain" start=disabled
sc stop "BITS" & sc config "BITS" start=disabled
sc stop "MapsBroker" & sc config "MapsBroker" start=disabled
sc stop "DoSvc" & sc config "DoSvc" start=disabled
sc stop "DiagTrack" & sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
:: Some basic and good registry tweaks with proper syntax and also putting the TCP values in the interfaces, not in the parameters.
for /f "tokens=3*" %%p in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s^|findstr /i /l "ServiceName"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
 	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
 	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
)
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
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "255" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
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
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMin /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMax /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMax /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMin /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMax /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v ValueMin /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v DcCacheExpirationTime /t REG_DWORD /d "1000" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v SeqMaxAckDelay /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v StoreAckTimeout /t REG_DWORD /d "65535" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v AckTimeout /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v BscAckFrequency /t REG_DWORD /d "2" /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\EOSNotify /f /v DiscontinueEOS /t REG_DWORD /d 1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify /f /v DiscontinueEOS /t REG_DWORD /d 1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify /f /v DontRemindMe /t REG_DWORD /d 1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify /f /v LastRunTimestamp /t REG_QWORD /d 0x0
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify /f /v TimestampOverride /t REG_QWORD /d 0x0
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify /f /v DontRemindMe /t REG_DWORD /d 1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify /f /v DateModified /t REG_QWORD /d 0x0
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify /f /v LastShown /t REG_QWORD /d 0x0
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Gwx /v DisableGwx /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableOSUpgrade /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade /v AllowOSUpgrade /t REG_DWORD /d 0 /f
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /f
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack /v DiagTrackAuthorization /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\SQMClient\IE /v CEIPEnable /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\SQMClient\IE /v SqmLoggerRunning /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\SQMClient\Reliability /v CEIPEnable /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\SQMClient\Reliability /v SqmLoggerRunning /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\SQMClient\Windows /v CEIPEnable /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\SQMClient\Windows /v SqmLoggerRunning /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\SQMClient\Windows /v DisableOptinExperience /t REG_DWORD /d 1 /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /v HaveUploadedForTarget /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AIT" /v AITEnable /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v DontRetryOnError /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v IsCensusDisabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v TaskEnableRun /t REG_DWORD /d 1 /f
for %%i in (InstallInfoCheck,ARPInfoCheck,MediaInfoCheck,FileInfoCheck) do reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Tracing" /v %%i /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags" /v UpgradeEligible /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" /f
:: Deleting some Windows and temporary files, they are useless in most cases.
del /q %softdir%\*
for /d %%x in (%softdir%\*) do @rd /s /q ^"%%x^"
if exist %oldwin% (rmdir /s /q %oldwin%)
del /q %temp%\*
for /d %%x in (%temp%\*) do @rd /s /q ^"%%x^"
del /q %wintemp%\*
for /d %%x in (%wintemp%\*) do @rd /s /q ^"%%x^"
:: Trying to remove OneDrive, it's one of the most useless thing Microsoft ever created.
if exist %ondir% (
    rmdir %ondir%
    taskkill /f /im OneDrive.exe
    wmic /node:"hostname" product where name="Microsoft OneDrive" call uninstall /nointeractive
)
:: Disabling and deleting useless Windows tasks.
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
schtasks /Change /DISABLE /TN "Microsoft\Windows\Setup\EOSNotify"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Setup\EOSNotify2"
schtasks /Delete /F /TN "Microsoft\Windows\Setup\EOSNotify"
schtasks /Delete /F /TN "Microsoft\Windows\Setup\EOSNotify2"
schtasks /Change /DISABLE /TN "Microsoft\Windows\End Of Support\Notify1"
schtasks /Change /DISABLE /TN "Microsoft\Windows\End Of Support\Notify2"
schtasks /Delete /F /TN "Microsoft\Windows\End Of Support\Notify1"
schtasks /Delete /F /TN "Microsoft\Windows\End Of Support\Notify2"
schtasks /Change /DISABLE /TN "Microsoft\Windows\SetupSQMTask"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\TelTask"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Application Experience\AitAgent"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /Change /DISABLE /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /Change /DISABLE /TN "Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"
schtasks /Delete /F /TN "Microsoft\Windows\SetupSQMTask"
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\TelTask"
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /Delete /F /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /Delete /F /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /Delete /F /TN "Microsoft\Windows\Application Experience\AitAgent"
schtasks /Delete /F /TN "Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"
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
taskkill /f /im SearchUI.exe
taskkill /f /im RemindersServer.exe
taskkill /f /im ShellExperienceHost.exe
taskkill /f /im MicrosoftEdge.exe
taskkill /f /im MicrosoftEdgeCP.exe
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" "%random%"
ren "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" "%random%"
ren "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe" "%random%"
ren "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy" "%random%"
:: And finally, we're clearing the event logs from the Microsoft's built-in softwares in Windows 10, this is generally to make the PC faster.
for /F "tokens=*" %%G in ('wevtutil el') DO (call :clearlogs "%%G")
:clearlogs
echo Clearing the log %1
wevtutil cl %1