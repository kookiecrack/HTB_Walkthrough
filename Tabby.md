# Optimum
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
