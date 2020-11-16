# Worker
## Reconnaissance

Port Scans

```
sudo masscan -p1-65535,U:1-65535 10.10.10.203 --rate=1000 -e tun0
sudo masscan -p1-65535 10.10.10.203 --rate=1000 -e tun0 > ports && ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//') && nmap -Pn -sV -sC -A -p$ports 10.10.10.203

sudo nmap -sC -sS -sV -A 10.10.10.203
sudo nmap -p- 10.10.10.203 --max-retries 0 -Pn
sudo nmap -p- -sU 10.10.10.203 --max-retries 0 -Pn
sudo nmap --script vuln 10.10.10.203
```
```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

```
PORT     STATE SERVICE
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
3690/tcp open  svn
```

```
kali@kali:~/HTB/worker$ nmap --script svn-brute --script-args svn-brute.repo=/home/kali/Tools/rockyou.txt -p 3690 10.10.10.203
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-12 02:43 EST
Nmap scan report for 10.10.10.203
Host is up (0.0099s latency).

PORT     STATE SERVICE
3690/tcp open  svn
| svn-brute:   
|_  Anonymous SVN detected, no authentication needed


kali@kali:~/HTB/worker$ svn info svn://10.10.10.203:3690
Path: .
URL: svn://10.10.10.203
Relative URL: ^/
Repository Root: svn://10.10.10.203
Repository UUID: 2fc74c5a-bc59-0744-a2cd-8b7d1d07c9a1
Revision: 5
Node Kind: directory
Last Changed Author: nathen
Last Changed Rev: 5
Last Changed Date: 2020-06-20 09:52:00 -0400 (Sat, 20 Jun 2020)

kali@kali:~/HTB/worker$ svn list svn://10.10.10.203:3690
dimension.worker.htb/
moved.txt
```

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Nov 12 02:19:02 2020
URL_BASE: http://10.10.10.203/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
SPEED_DELAY: 10 milliseconds

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.203/ ----
==> DIRECTORY: http://10.10.10.203/aspnet_client/                                                                
                                                                                                                 
---- Entering directory: http://10.10.10.203/aspnet_client/ ----
==> DIRECTORY: http://10.10.10.203/aspnet_client/system_web/                                                     
                                                                                                                 
---- Entering directory: http://10.10.10.203/aspnet_client/system_web/ ----
                                                                                                                 
-----------------
END_TIME: Thu Nov 12 02:28:47 2020
DOWNLOADED: 13836 - FOUND: 0
```
```
- Checklist port 80
	- [ ] What does the application do?
	- [ ] What language is it written in? aspx
	- [ ] What server software is the application running on? IIS 10.0

- Checklist port 5985
	- [ ] What does the application do?
	- [ ] What language is it written in?
	- [ ] What server software is the application running on? Server: Microsoft-HTTPAPI/2.0

```

```
kali@kali:~/HTB/worker$ svn export svn://10.10.10.203:3690/moved.txt
A    moved.txt                                                                                                    
Export complete.                                                                                                  kali@kali:~/HTB/worker$ cat moved.txt                                                                             
This repository has been migrated and will no longer be maintaned here.                                           
You can find the latest version at: http://devops.worker.htb                                                      
                                                                                                                  
// The Worker team :)                                                                                             
                                                                                                                  
kali@kali:~/HTB/worker$ svn export svn://10.10.10.203:3690/dimension.worker.htb
A    dimension.worker.htb                                                                                         
A    dimension.worker.htb/LICENSE.txt                                                                             
A    dimension.worker.htb/README.txt
A    dimension.worker.htb/assets       
A    dimension.worker.htb/assets/css        
A    dimension.worker.htb/assets/css/fontawesome-all.min.css
A    dimension.worker.htb/assets/css/main.css
A    dimension.worker.htb/assets/css/noscript.css
A    dimension.worker.htb/assets/js 
A    dimension.worker.htb/assets/js/breakpoints.min.js
A    dimension.worker.htb/assets/js/browser.min.js
A    dimension.worker.htb/assets/js/jquery.min.js
A    dimension.worker.htb/assets/js/main.js
A    dimension.worker.htb/assets/js/util.js
A    dimension.worker.htb/assets/sass
A    dimension.worker.htb/assets/sass/base
A    dimension.worker.htb/assets/sass/base/_page.scss
A    dimension.worker.htb/assets/sass/base/_reset.scss
A    dimension.worker.htb/assets/sass/base/_typography.scss
A    dimension.worker.htb/assets/sass/components
A    dimension.worker.htb/assets/sass/components/_actions.scss
A    dimension.worker.htb/assets/sass/components/_box.scss
A    dimension.worker.htb/assets/sass/components/_button.scss
A    dimension.worker.htb/assets/sass/components/_form.scss
A    dimension.worker.htb/assets/sass/components/_icon.scss
A    dimension.worker.htb/assets/sass/components/_icons.scss
A    dimension.worker.htb/assets/sass/components/_image.scss
A    dimension.worker.htb/assets/sass/components/_list.scss
A    dimension.worker.htb/assets/sass/components/_table.scss
A    dimension.worker.htb/assets/sass/layout
A    dimension.worker.htb/assets/sass/layout/_bg.scss
A    dimension.worker.htb/assets/sass/layout/_footer.scss 
A    dimension.worker.htb/assets/sass/layout/_header.scss 
A    dimension.worker.htb/assets/sass/layout/_main.scss
A    dimension.worker.htb/assets/sass/layout/_wrapper.scss
A    dimension.worker.htb/assets/sass/libs
A    dimension.worker.htb/assets/sass/libs/_breakpoints.scss
A    dimension.worker.htb/assets/sass/libs/_functions.scss
A    dimension.worker.htb/assets/sass/libs/_mixins.scss
A    dimension.worker.htb/assets/sass/libs/_vars.scss
A    dimension.worker.htb/assets/sass/libs/_vendor.scss
A    dimension.worker.htb/assets/sass/main.scss
A    dimension.worker.htb/assets/sass/noscript.scss
A    dimension.worker.htb/assets/webfonts
A    dimension.worker.htb/assets/webfonts/fa-brands-400.eot
A    dimension.worker.htb/assets/webfonts/fa-brands-400.svg
A    dimension.worker.htb/assets/webfonts/fa-brands-400.ttf
A    dimension.worker.htb/assets/webfonts/fa-brands-400.woff
A    dimension.worker.htb/assets/webfonts/fa-brands-400.woff2
A    dimension.worker.htb/images                       
A    dimension.worker.htb/images/bg.jpg        
A    dimension.worker.htb/images/overlay.png       
A    dimension.worker.htb/images/pic01.jpg
A    dimension.worker.htb/images/pic02.jpg                                                                        
A    dimension.worker.htb/images/pic03.jpg                                                                        
A    dimension.worker.htb/index.html                                                                              
Exported revision 5.                                                        



Add devops.worker.htb to /etc/hosts
kali@kali:~/HTB/worker$ svn checkout svn://worker.htb
Skipped 'dimension.worker.htb' -- An obstructing working copy was found
   C moved.txt
Checked out revision 5.
kali@kali:~/HTB/worker$ ls
dimension.worker.htb  moved.txt  output  ports  svn_extractor.py  www
kali@kali:~/HTB/worker$ svn checkout -r 1 svn://worker.htb
Skipped 'moved.txt' -- Node remains in conflict
Skipped 'dimension.worker.htb' -- An obstructing working copy was found
Checked out revision 1.
kali@kali:~/HTB/worker$ svn checkout -r 2 svn://worker.htb
Skipped 'moved.txt' -- Node remains in conflict
A    deploy.ps1
Skipped 'dimension.worker.htb' -- An obstructing working copy was found
Checked out revision 2.
kali@kali:~/HTB/worker$ cat deploy.ps1 
$user = "nathen" 
$plain = "wendel98"
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
kali@kali:~/HTB/worker$ 
