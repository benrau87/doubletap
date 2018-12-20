# Worksheet
Use the outputs from the doubletap scan here, run any necessary secondary scans included in the templates
in order to further enumerate the target. Based off findings make an audit list and proceed to Google.

## General Information
```
Hostname :
IP Address:
OS :
Version :
```
------------------------------------------------------------------------
Initial Access
------------------------------------------------------------------------
## Services (eg. SSH, SQL, SMTP, UDP(SNMP)...)
```




```

## NFS/SMB Drives
```


```

## Web Applications/Technologies (eg PHP, Apache, CMS...)
```



```

## Login Pages
```

```

## Found Users/Services/Credentials
```

```

## Audit Order
List based of perceived probability of success. Note steps taken.
```
1)
2)
3)
4)
5)
6)
...

## Notes
```


```

## Exploit Steps
```


```

------------------------------------------------------------------------
Privesc
------------------------------------------------------------------------
Follow the general order below for least to most intensive

For Linux Limited Shells:
python -c 'import pty; pty.spawn("/bin/sh")'
Linux Path:
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

## Users/Services/Credentials/Group Memebership
Try for reused passwords across accounts:
cat /etc/passwd
sudo - <user> -c 'ls'
runuser -l <user> -c 'ls'

```


```

## Kernel Vulnerablities
Get specific OS/patch versions and list possible exploits here
uname -a
searchsploit <version>
```


```

## Scan Outputs
Use linenum, or other scripts to generate report
``` 
1) Unmonted disks (df -h or fstab entries)
2) Bash history (check .bash_history)
3) Config files with passwords
4) Cron jobs scheduled 
5) SSH keys and config (/etc/ssh or .ssh)
6) Log files (/var/log)
7) SUID executables
8) Internal services (netstat, ps aux find related process version and check for exploit)

https://payatu.com/guide-linux-privilege-escalation/
```

## Notes
```


```

## Exploit Steps
```


```