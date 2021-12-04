# A quick script I pieced together from a few sources to do a bit of hardening on some of my Windows systems

# Harden OS: enable DEP, enable ASLR, enable SEHOP, disable DNS multicast, disable NetBIOS, protect LSASS process, disable WDigest
Set-Processmitigation -System -Enable DEP,BottomUp,SEHOP
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 1 -Force
wmic /interactive:off nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2
New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name AuditLevel -Value 8 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -Value 00000001 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -value 0 -Force

# Basic Firewall: enable all profiles, disable all default rules, allow all outbound traffic, deny all inbound traffic except the essentials (ICMP, SMB, RDP, HTTP/S, etc)
Set-NetFirewallProfile -Profile @('Domain', 'Private', 'Public') -Enabled True
Get-NetFirewallRule -Name * | Disable-NetFirewallRule
Set-NetFirewallProfile –Name @('Domain', 'Private', 'Public') –DefaultOutboundAction Allow
Set-NetFirewallProfile –Name @('Domain', 'Private', 'Public') –DefaultInboundAction Block
New-NetFirewallRule -DisplayName 'Allow-ICMP-Inbound' -Profile @('Domain', 'Private', 'Public') -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 
New-NetFirewallRule -DisplayName 'Allow-SMB-Inbound' -Profile @('Domain', 'Private', 'Public') -Direction Inbound -Action Allow -Protocol 'TCP' -LocalPort '445'
New-NetFirewallRule -DisplayName 'Allow-RDP-Inbound' -Profile @('Domain', 'Private', 'Public') -Direction Inbound -Action Allow -Protocol 'TCP' -LocalPort '3389'
New-NetFirewallRule -DisplayName 'Allow-HTTP-Inbound' -Profile @('Domain', 'Private', 'Public') -Direction Inbound -Action Allow -Protocol 'TCP' -LocalPort '80'
New-NetFirewallRule -DisplayName 'Allow-HTTPS-Inbound' -Profile @('Domain', 'Private', 'Public') -Direction Inbound -Action Allow -Protocol 'TCP' -LocalPort '443'

# Harden SMB: Uninstall SMBv1, disable SMBv2 server, and disable SMBv3 compression
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Confirm:$false
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name DisableCompression -Value 1 -Type DWORD -Force:$true

# Harden RDP: enable, require NLA, configure crypto, assuming you will manually set up 2FA right?
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name 'SecurityLayer' -value 2
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name 'MinEncryptionLevel' -value 3

# Harden SChannel: disable SSL, configure TLS, disable legacy cipher suites, configure .NET crypto
$SChannelRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
New-Item $SChannelRegPath"\TLS 1.3\Server" -Force
New-Item $SChannelRegPath"\TLS 1.3\Client" -Force
New-ItemProperty -Path $SChannelRegPath"\TLS 1.3\Server" -Name Enabled -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.3\Server" -Name DisabledByDefault -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.3\Client" -Name Enabled -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.3\Client" -Name DisabledByDefault -Value 0 -PropertyType DWORD
New-Item $SChannelRegPath"\TLS 1.2\Server" -Force
New-Item $SChannelRegPath"\TLS 1.2\Client" -Force
New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Server" -Name Enabled -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Server" -Name DisabledByDefault -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Client" -Name Enabled -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.2\Client" -Name DisabledByDefault -Value 0 -PropertyType DWORD
New-Item $SChannelRegPath"\TLS 1.1\Server" -Force
New-Item $SChannelRegPath"\TLS 1.1\Client" -Force
New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Server" -Name Enabled -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Server" -Name DisabledByDefault -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Client" -Name Enabled -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.1\Client" -Name DisabledByDefault -Value 0 -PropertyType DWORD
New-Item $SChannelRegPath"\TLS 1.0\Server" -Force
New-Item $SChannelRegPath"\TLS 1.0\Client" -Force
New-ItemProperty -Path $SChannelRegPath"\TLS 1.0\Server" -Name Enabled -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.0\Server" -Name DisabledByDefault -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.0\Client" -Name Enabled -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\TLS 1.0\Client" -Name DisabledByDefault -Value 1 -PropertyType DWORD
New-Item $SChannelRegPath"\SSL 3.0\Server" -Force
New-Item $SChannelRegPath"\SSL 3.0\Client" -Force
New-ItemProperty -Path $SChannelRegPath"\SSL 3.0\Server" -Name Enabled -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\SSL 3.0\Server" -Name DisabledByDefault -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\SSL 3.0\Client" -Name Enabled -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\SSL 3.0\Client" -Name DisabledByDefault -Value 1 -PropertyType DWORD
New-Item $SChannelRegPath"\SSL 2.0\Server" -Force
New-Item $SChannelRegPath"\SSL 2.0\Client" -Force
New-ItemProperty -Path $SChannelRegPath"\SSL 2.0\Server" -Name Enabled -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\SSL 2.0\Server" -Name DisabledByDefault -Value 1 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\SSL 2.0\Client" -Name Enabled -Value 0 -PropertyType DWORD
New-ItemProperty -Path $SChannelRegPath"\SSL 2.0\Client" -Name DisabledByDefault -Value 1 -PropertyType DWORD
Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" 
Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_SHA"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_MD5"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA256"
Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_GCM_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_GCM_SHA256"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_CBC_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_CBC_SHA256"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA384"
Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA256"
$DotNetRegPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
New-ItemProperty -path $DotNetRegPath -name 'SystemDefaultTlsVersions' -value 1 -PropertyType DWORD
New-ItemProperty -path $DotNetRegPath -name 'SchUseStrongCrypto' -value 1 -PropertyType DWORD
$DotNetRegPath64 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
New-ItemProperty -path $DotNetRegPath64 -name 'SystemDefaultTlsVersions' -value 1 -PropertyType DWORD
New-ItemProperty -path $DotNetRegPath64 -name 'SchUseStrongCrypto' -value 1 -PropertyType DWORD

# Harden Defender: reset, enable sandbox, enable ASR rules
& $env:programfiles\"Windows Defender"\MpCmdRun.exe -RestoreDefaults
setx /M MP_FORCE_USE_SANDBOX 1
# Block Office Child Process Creation 
Add-MpPreference -AttackSurfaceReductionRules_Ids 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' -AttackSurfaceReductionRules_Actions Enabled
# Block Process Injection
Add-MpPreference -AttackSurfaceReductionRules_Ids '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' -AttackSurfaceReductionRules_Actions Enabled
# Block Win32 API calls in macros
Add-MpPreference -AttackSurfaceReductionRules_Ids '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' -AttackSurfaceReductionRules_Actions Enabled
# Block Office from creating executables
Add-MpPreference -AttackSurfaceReductionRules_Ids '3B576869-A4EC-4529-8536-B80A7769E899' -AttackSurfaceReductionRules_Actions Enabled
# Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' -AttackSurfaceReductionRules_Actions Enabled
# Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' -AttackSurfaceReductionRules_Actions Enabled
# Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 'D3E037E1-3EB8-44C8-A917-57927947596D' -AttackSurfaceReductionRules_Actions Enabled
# Block lsass cred theft
Add-MpPreference -AttackSurfaceReductionRules_Ids '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' -AttackSurfaceReductionRules_Actions Enabled
# Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' -AttackSurfaceReductionRules_Actions Enabled
# Block Adobe Reader from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' -AttackSurfaceReductionRules_Actions Enabled
# Block persistence through WMI event subscription
Add-MpPreference -AttackSurfaceReductionRules_Ids 'e6db77e5-3df2-4cf1-b95a-636979351e5b' -AttackSurfaceReductionRules_Actions Enabled
# Block process creations originating from PSExec and WMI commands
Add-MpPreference -AttackSurfaceReductionRules_Ids 'd1e49aac-8f56-4280-b9ba-993a6d77406c' -AttackSurfaceReductionRules_Actions Enabled
# Block executable files from running unless they meet a prevalence, age, or trusted list criterion
Add-MpPreference -AttackSurfaceReductionRules_Ids '01443614-cd74-433a-b99e-2ecdc07bfc25' -AttackSurfaceReductionRules_Actions Enabled

# Harden Office: disable macros, enable Protected mode, disable DDE
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options" -Name DontUpdateLinks -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail" -Name DontUpdateLinks -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options" -Name DontUpdateLinks -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail" -Name DontUpdateLinks -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options" -Name DontUpdateLinks -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail" -Name DontUpdateLinks -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\12.0\Publisher\Security" -Name vbawarnings -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\12.0\Word\Security" -Name vbawarnings -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\14.0\Publisher\Security" -Name vbawarnings -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\14.0\Word\Security" -Name vbawarnings -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\Outlook\Security" -Name markinternalasunsafe -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\Word\Security" -Name blockcontentexecutionfrominternet -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\Excel\Security" -Name blockcontentexecutionfrominternet -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" -Name blockcontentexecutionfrominternet -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\Word\Security" -Name vbawarnings -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\15.0\Publisher\Security" -Name vbawarnings -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security" -Name markinternalasunsafe -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security" -Name blockcontentexecutionfrominternet -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security" -Name blockcontentexecutionfrominternet -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" -Name blockcontentexecutionfrominternet -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security" -Name vbawarnings -Value 4 -Force
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Publisher\Security" -Name vbawarnings -Value 4 -Force
