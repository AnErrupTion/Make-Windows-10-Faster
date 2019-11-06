@echo off
title Optimize Windows - by ErrupTion_
set /p mtu=Enter your MTU : 
set /p nettype=Are you on Ethernet or Wi-Fi? 
set /p mbram=Enter your ram in MB, example : if you have 4 GB, you will enter 4096 : 
cls
netsh int tcp reset
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
netsh interface ipv4 set subinterface "Local Area Connection" mtu=%mtu% store=persistent
netsh interface ipv6 set subinterface "Local Area Connection" mtu=%mtu% store=persistent
netsh interface ipv4 set subinterface "Wireless Network Connection" mtu=%mtu% store=persistent
netsh interface ipv6 set subinterface "Wireless Network Connection" mtu=%mtu% store=persistent
wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("1.1.1.1", "1.0.0.1")
ipconfig /flushdns
setlocal EnableDelayedExpansion
SET validInterfaces=%regBranch:\0\0=\0%
IF /I NOT "%validInterfaces:~-2%"=="\0" (
 SET validInterfaces=%validInterfaces%\0
)

SET regBrnch=HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
FOR /F "tokens=1-8 delims=\" %%i IN ( '%Sys32%reg.exe Query %regBrnch%' ) DO (
 %Sys32%reg.exe QUERY %regBrnch%\%%p /v DhcpIPAddress
 IF !ERRORLEVEL! EQU 0 (
 reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
 reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
 reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%p" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
 )
)
endlocal
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
set loctemp="%localappdata%\Temp"
set wintemp="%systemroot%\Temp"
set prefetch="%systemroot%\Prefetch"
IF EXIST "%loctemp%" (
    cd /d %loctemp%
    for /F "delims=" %%i in ('dir /b') do (rmdir "%%i" /s/q || del "%%i" /s/q)
)
IF EXIST "%wintemp%" (
    cd /d %wintemp%
    for /F "delims=" %%i in ('dir /b') do (rmdir "%%i" /s/q || del "%%i" /s/q)
)
IF EXIST "%prefetch%" (
    cd /d %prefetch%
    for /F "delims=" %%i in ('dir /b') do (rmdir "%%i" /s/q || del "%%i" /s/q)
)
taskkill /f /im CryptoTabUpdate.exe & echo Killed CryptoTabUpdate.exe
taskkill /f /im CryptoTabCrashHandler64.exe & echo Killed CryptoTabCrashHandler64.exe
taskkill /f /im CryptoTabCrashHandler.exe & echo Killed CryptoTabCrashHandler.exe
taskkill /f /im BraveUpdate.exe & echo Killed BraveUpdate.exe
taskkill /f /im HTTPDebuggerSvc.exe & echo Killed HTTPDebuggerSvc.exe
taskkill /f /im MicrosoftEdgeUpdate.exe & echo Killed MicrosoftEdgeUpdate.exe
taskkill /f /im ChromeUpdate.exe & echo Killed ChromeUpdate.exe
net stop "wsearch" & sc config "wsearch" start=disabled & echo Disabled Windows Search
net stop "wuauserv" & sc config "wuauserv" start=disabled & echo Disabled Windows Update
net stop "sysmain" & sc config "sysmain" start=disabled & echo Disabled SysMain
net stop "superfetch" & sc config "superfetch" start=disabled & echo Disabled Superfetch
net stop "trustedinstaller" & sc config "trustedinstaller" start=disabled & echo Disabled TrustedInstaller
net stop "HTTPDebuggerPro" & sc config "HTTPDebuggerPro" start=disabled & echo Disabled HTTP Debugger Pro Service
net stop "BITS" & sc config "BITS" start=disabled & echo Disabled BITS
bcdedit /deletevalue useplatformclock
bcdedit /set IncreaseUserVA %mbram%
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg /hibernate off