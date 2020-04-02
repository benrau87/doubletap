#!/usr/bin/python3
import subprocess
import netifaces as ni
import re
import multiprocessing
from multiprocessing import Process, Queue
import os
import time
import fileinput
import atexit
import sys
import socket
import requests
import argparse

start = time.time()
default_dirs = str(os.environ["HOME"]) + "/"
myip = ni.ifaddresses("eth0")[ni.AF_INET][0]['addr']

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Creates a function for multiprocessing.
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip, port))
    jobs.append(p)
    p.start()
    return

# Functions for service specific connections.
def connect_to_port(ip_address, port, service):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip_address, int(port)))
    banner = s.recv(1024)
    banner = banner.decode("utf-8") #### change
    if service == "ftp":
        s.send("USER anonymous\r\n")
        user = s.recv(1024)
        s.send("PASS anonymous\r\n")
        password = s.recv(1024)
        total_communication = banner + "\r\n" + user + "\r\n" + password
        write_to_file(ip_address, "ftp-connect", total_communication)
    elif service == "smtp":
        total_communication = banner + "\r\n"
        write_to_file(ip_address, "smtp-connect", total_communication)
    elif service == "ssh":
        total_communication = banner
        print("THIS SIS THE EFFING PROBLEM?_________________________________", banner)
        write_to_file(ip_address, "ssh-connect", total_communication)
    elif service == "pop3":
        s.send("USER root\r\n")
        user = s.recv(1024)
        s.send("PASS root\r\n")
        password = s.recv(1024)
        total_communication = banner + user + password
        write_to_file(ip_address, "pop3-connect", total_communication)
    s.close()

# Functions for writing into templates
def write_to_file(ip_address: str, enum_type: str, data: int):

    file_path_linux = "%s%s/%s-linux-exploit-steps.md" % (dirs, ip_address, ip_address)
    file_path_windows = "%s%s/%s-windows-exploit-steps.md" % (dirs, ip_address, ip_address)
    paths = [file_path_linux, file_path_windows]
    #print(bcolors.OKGREEN + "INFO: Writing " + enum_type + " to template files:\n" + file_path_linux + "   \n" + file_path_windows + bcolors.ENDC + "\n")

    for path in paths:
        #        if enum_type == "portscan":
        #            subprocess.getoutput("replace INSERTTCPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "dirb":
            subprocess.getoutput("replace INSERTDIRBSCAN \"" + data + "\"  -- " + path)
        if enum_type == "dirbssl":
            subprocess.getoutput("replace INSERTDIRBSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "nikto":
            subprocess.getoutput("replace INSERTNIKTOSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ftp-connect":
            subprocess.getoutput("replace INSERTFTPTEST \"" + data + "\"  -- " + path)
        if enum_type == "smtp-connect":
            subprocess.getoutput("replace INSERTSMTPCONNECT \"" + data + "\"  -- " + path)
        if enum_type == "ssh-connect":
            subprocess.getoutput("replace INSERTSSHCONNECT \"" + data + "\"  -- " + path)
        if enum_type == "pop3-connect":
            subprocess.getoutput("replace INSERTPOP3CONNECT \"" + data + "\"  -- " + path)
        if enum_type == "curl":
            subprocess.getoutput("replace INSERTCURLHEADER \"" + data + "\"  -- " + path)
        if enum_type == "wig":
            subprocess.getoutput("replace INSERTWIGSCAN \"" + data + "\"  -- " + path)
        if enum_type == "wigssl":
            subprocess.getoutput("replace INSERTWIGSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "smbmap":
            subprocess.getoutput("replace INSERTSMBMAP \"" + data + "\"  -- " + path)
        if enum_type == "rpcmap":
            subprocess.getoutput("replace INSERTRPCMAP \"" + data + "\"  -- " + path)
        if enum_type == "samrdump":
            subprocess.getoutput("replace INSERTSAMRDUMP \"" + data + "\"  -- " + path)
        if enum_type == "vulnscan":
            subprocess.getoutput("replace INSERTVULNSCAN \"" + data + "\"  -- " + path)
        if enum_type == "nfsscan":
            subprocess.getoutput("replace INSERTNFSSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ssl-scan":
            subprocess.getoutput("replace INSERTSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "parsero":
            subprocess.getoutput("replace INSERTROBOTS \"" + data + "\"  -- " + path)
        if enum_type == "sshscan":
            subprocess.getoutput("replace INSERTSSHBRUTE \"" + str(data) + "\"  -- " + path)
        if enum_type == "fulltcpscan":
            subprocess.getoutput("replace INSERTFULLTCPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "udpscan":
            subprocess.getoutput("replace INSERTUDPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "waf":
            subprocess.getoutput("replace INSERTWAFSCAN \"" + data + "\"  -- " + path)
        if enum_type == "wafssl":
            subprocess.getoutput("replace INSERTWAFSSLSCAN \"" + data + "\"  -- " + path)
        if enum_type == "ldap":
            subprocess.getoutput("replace INSERTLDAPSCAN \"" + data + "\"  -- " + path)
        if enum_type == "kerb":
            subprocess.getoutput("replace INSERTKERBSCAN \"" + data + "\"  -- " + path)
    return


def dirb(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting DIRB scan for {ip_address} : {port} {bcolors.ENDC}")
    DIRBSCAN = f"gobuster dir -z -u {url_start}://{ip_address}:{port} -w /usr/share/wordlists/dirb/common.txt -P /opt/doubletap-git/wordlists/quick_hit.txt -U /opt/doubletap-git/wordlists/quick_hit.txt -t 20 | sed -r 's/\x1B\[([0-9]{1, 2}(;[0-9]{1, 2})?)?[mGK]//g' | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt"
    results_dirb = subprocess.getoutput(DIRBSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with DIRB-scan for {ip_address} {bcolors.ENDC}")
    #print(results_dirb)
    write_to_file(ip_address, "dirb", results_dirb)
    return


def dirbssl(ip_address, port, url_start):
    print(f'{bcolors.HEADER}INFO: Starting DIRBSSL scan for {ip_address} : {port} {bcolors.ENDC}')
    DIRBSCAN = f"gobuster dir -z -u {url_start}://{ip_address}:{port} -e -f -n -w /usr/share/wordlists/dirb/common.txt -P /opt/doubletap-git/wordlists/quick_hit.txt -U /opt/doubletap-git/wordlists/quick_hit.txt -t 20 | sed -r 's/\x1B\[([0-9]{1, 2}(;[0-9]{1, 2})?)?[mGK]//g' | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt"
    results_dirb = subprocess.getoutput(DIRBSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with DIRBSSL-scan for {ip_address}{bcolors.ENDC}")
    #print(results_dirb)
    write_to_file(ip_address, "dirbssl", results_dirb)
    return


def wig(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting WIG scan for {ip_address}{bcolors.ENDC}")
    WIGSCAN = f"wig-git -t 20 -u {url_start}://{ip_address}:{port} -q -d | sed -r 's/\x1B\[([0-9]{1, 2}(;[0-9]{1, 2})?)?[mGK]//g' | tee -a {dirs}{ip_address}/webapp_scans/wig-{ip_address}.txt"
    results_wig = subprocess.getoutput(WIGSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with WIG-scan for {ip_address}{bcolors.ENDC}")
    #print(results_wig)
    write_to_file(ip_address, "wig", results_wig)
    return


def wigssl(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting WIGSSL scan for {ip_address}{bcolors.ENDC}")
    WIGSCAN = f"wig-git -t 20 -u {url_start}://{ip_address}:{port} -q -d | sed -r 's/\x1B\[([0-9]{1, 2}(;[0-9]{1, 2})?)?[mGK]//g' | tee -a {dirs}{ip_address}/webapp_scans/wig-{ip_address}.txt"
    results_wig = subprocess.getoutput(WIGSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with WIGSSL-scan for {ip_address}{bcolors.ENDC}")
    #print(results_wig)
    write_to_file(ip_address, "wigssl", results_wig)
    return


def parsero(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting ROBOTS scan for {ip_address}{bcolors.ENDC}")
    ROBOTSSCAN = f"parsero-git -o -u {url_start}://{ip_address}:{port} | grep OK | grep -o 'http.*' | sed -r 's/\x1B\[([0-9]{1, 2}(;[0-9]{1, 2})?)?[mGK]//g' | tee -a {dirs}{ip_address}/webapp_scans/dirb-{ip_address}.txt"
    results_parsero = subprocess.getoutput(ROBOTSSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with ROBOTS-scan for {ip_address}{bcolors.ENDC}")
    #print(results_parsero)
    write_to_file(ip_address, "parsero", results_parsero)
    return


def waf(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting WAF scan for {ip_address}{bcolors.ENDC}")
    WAFSCAN = f"wafw00f {url_start}://{ip_address}:{port} -a | tee -a {dirs}{ip_address}/webapp_scans/waf-{ip_address}.txt"
    results_waf = subprocess.getoutput(WAFSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with WAF-scan for {ip_address}{bcolors.ENDC}")
    #print(results_waf)
    write_to_file(ip_address, "waf", results_waf)
    return


def wafssl(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting WAFSSL scan for {ip_address}{bcolors.ENDC}")
    WAFSSLSCAN = f"wafw00f {url_start}://{ip_address}:{port} -a | tee -a {dirs}{ip_address}/webapp_scans/waf-{ip_address}.txt"
    results_wafssl = subprocess.getoutput(WAFSSLSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with WAFSSL-scan for {ip_address}{bcolors.ENDC}")
    #print(results_wafssl)
    write_to_file(ip_address, "wafssl", results_wafssl)
    return


def nikto(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting NIKTO scan for {ip_address}{bcolors.ENDC}")
    NIKTOSCAN = f"nikto -maxtime 5m -h {url_start}://{ip_address}:{port} | tee -a {dirs}{ip_address}/webapp_scans/nikto-{url_start}-{ip_address}.txt"
    results_nikto = subprocess.getoutput(NIKTOSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with NIKTO-scan for {ip_address}{bcolors.ENDC}")
    #print(results_nikto)
    write_to_file(ip_address, "nikto", results_nikto)
    return


def ssl(ip_address, port, url_start):
    print(f"{bcolors.HEADER}INFO: Starting SSL scan for {ip_address}{bcolors.ENDC}")
    SSLSCAN = f"sslscan {ip_address}:{port} |  sed -r 's/\x1B\[([0-9]{1, 2}(;[0-9]{1, 2})?)?[mGK]//g' |  tee {dirs}{ip_address}/webapp_scans/ssl_scan_{ip_address}"
    #print(bcolors.HEADER + SSLSCAN + bcolors.ENDC)
    results_ssl = subprocess.getoutput(SSLSCAN)
    print(f"{bcolors.OKGREEN}INFO: Finished with SSL-scan for {ip_address}{bcolors.ENDC}")
    #print(results_ssl)
    write_to_file(ip_address, "ssl-scan", results_ssl)
    return


def httpEnum(ip_address, port):
    #print(bcolors.HEADER + "INFO: Detected http on " + ip_address + ":" + port + bcolors.ENDC)
    print(bcolors.HEADER + "INFO: Starting WEB app based scans for " + ip_address + ":" + port + bcolors.ENDC)
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address, port, "http"))
    nikto_process.start()
    parsero_process = multiprocessing.Process(target=parsero, args=(ip_address, port, "http"))
    parsero_process.start()
    wig_process = multiprocessing.Process(target=wig, args=(ip_address, port, "http"))
    wig_process.start()
    waf_process = multiprocessing.Process(target=waf, args=(ip_address, port, "http"))
    waf_process.start()
    #print(bcolors.HEADER + "INFO: Checking for response on port " + port + bcolors.ENDC)
    url = "http://" + ip_address + ":" + port + "/xxxxxxx"
    response = requests.get(url)
    #print("")
    #print(response)
    if response.status_code == 404:  # could also check == requests.codes.ok
        #print(bcolors.HEADER + "INFO: Response was 404 on port " + port + ", perfoming directory scans" + bcolors.ENDC)
        dirb_process = multiprocessing.Process(target=dirb, args=(ip_address, port, "http"))
        dirb_process.start()
    else:
        print(
            bcolors.WARNING + "INFO: Response was not 404 on port " + port + ", skipping directory scans" + bcolors.ENDC)
    print("")
    return


def httpsEnum(ip_address, port):
    #print(bcolors.HEADER + "INFO: Detected https on " + ip_address + ":" + port + bcolors.ENDC)
    print(bcolors.HEADER + "INFO: Starting WEB based scans for " + ip_address + ":" + port + bcolors.ENDC)
    nikto_process = multiprocessing.Process(target=nikto, args=(ip_address, port, "https"))
    nikto_process.start()
    parsero_process = multiprocessing.Process(target=parsero, args=(ip_address, port, "https"))
    parsero_process.start()
    ssl_process = multiprocessing.Process(target=ssl, args=(ip_address, port, "https"))
    ssl_process.start()
    wig_process = multiprocessing.Process(target=wigssl, args=(ip_address, port, "https"))
    wig_process.start()
    waf_process = multiprocessing.Process(target=wafssl, args=(ip_address, port, "https"))
    waf_process.start()
    print("")
    #print(bcolors.HEADER + "INFO: Checking for response on port " + port + bcolors.ENDC)
    url = "https://" + ip_address + ":" + port + "/xxxxxxx"
    response = requests.get(url)
    #print(response)
    if response.status_code == 404:  # could also check == requests.codes.ok
        #print(bcolors.HEADER + "INFO: Response was 404 on port " + port + ", perfoming directory scans" + bcolors.ENDC)
        dirb_ssl_process = multiprocessing.Process(target=dirbssl, args=(ip_address, port, "https"))
        dirb_ssl_process.start()
    else:
        print(
            bcolors.WARNING + "INFO: Response was not 404 on port " + port + ", skipping directory scans" + bcolors.ENDC)
    print("")
    return


def mssqlEnum(ip_address, port):
    #print(bcolors.HEADER + "INFO: Detected MS-SQL on " + ip_address + ":" + port + bcolors.ENDC)
    print(bcolors.HEADER + "INFO: Starting MSSQL based scan for " + ip_address + ":" + port + bcolors.ENDC)
    MSSQLSCAN = f"nmap -sV -Pn -p {port} --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN {dirs}{ip_address}/service_scans/mssql_{ip_address}.nmap %s"
    #print(bcolors.HEADER + MSSQLSCAN + bcolors.ENDC)
    mssql_results = subprocess.getoutput(MSSQLSCAN)
    print(bcolors.OKGREEN + "INFO: Finished with MSSQL-scan for " + ip_address + bcolors.ENDC)
    #print(mssql_results)
    return


def smtpEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting SMTP based scan on " + ip_address + ":" + port + bcolors.ENDC)
    connect_to_port(ip_address, port, "smtp")
    SMTPSCAN = f"nmap -sV -Pn -p {port} --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 {ip_address} -oN {dirs}{ip_address}/service_scans/smtp_{ip_address}.nmap"
    #print(bcolors.HEADER + SMTPSCAN + bcolors.ENDC)
    smtp_results = subprocess.getoutput(SMTPSCAN)
    print(bcolors.OKGREEN + "INFO: Finished with SMTP-scan for " + ip_address + bcolors.ENDC)
    #print(smtp_results)
    write_to_file(ip_address, "smtp-connect", smtp_results)
    return


def smbEnum(ip_address, port):
    #print(bcolors.HEADER + "INFO: Detected SMB on " + ip_address + ":" + port)
    print(bcolors.HEADER + "INFO: Starting SMB based scans for " + ip_address + ":" + port + bcolors.ENDC)
    SMBMAP = f"smbmap -H {ip_address} | tee {dirs}{ip_address}/service_scans/smbmap_{ip_address}"
    smbmap_results = subprocess.getoutput(SMBMAP)
    print(bcolors.OKGREEN + "INFO: Finished with SMBMap-scan for " + ip_address + bcolors.ENDC)
    #print(smbmap_results)
    write_to_file(ip_address, "smbmap", smbmap_results)
    return


def rpcEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting RPC based scan on " + ip_address + ":" + port + bcolors.ENDC)
    RPCMAP = f"enum4linux -a {ip_address}  | tee {dirs}{ip_address}/service_scans/rpcmap_{ip_address}"
    rpcmap_results = subprocess.getoutput(RPCMAP)
    print(bcolors.OKGREEN + "INFO: Finished with RPC-scan for " + ip_address + bcolors.ENDC)
    #print(rpcmap_results)
    write_to_file(ip_address, "rpcmap", rpcmap_results)
    return


def samrEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting SAMR based scan on " + ip_address + ":" + port + bcolors.ENDC)
    SAMRDUMP = f"impacket-samrdump {ip_address} | tee {dirs}{ip_address}/service_scans/samrdump_{ip_address}"
    samrdump_results = subprocess.getoutput(SAMRDUMP)
    print(bcolors.OKGREEN + "INFO: Finished with SAMR-scan for " + ip_address + bcolors.ENDC)
    #print(samrdump_results)
    write_to_file(ip_address, "samrdump", samrdump_results)
    return


def ftpEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting FTP based scan on " + ip_address + ":" + port + bcolors.ENDC)
    connect_to_port(ip_address, port, "ftp")
    FTPSCAN = f"nmap -sV -Pn -vv -p {port} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN {dirs}{ip_address}/service_scans/ftp_{ip_address}.nmap {ip_address}"
    #print(bcolors.HEADER + FTPSCAN + bcolors.ENDC)
    ftp_results = subprocess.getoutput(FTPSCAN)
    print(bcolors.OKGREEN + "INFO: Finished with FTP-scan for " + ip_address + bcolors.ENDC)
    write_to_file(ip_address, "ftp-connect", ftp_results)
    #print(results_ftp)
    return


def ldapEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting LDAP based scan on " + ip_address + ":" + port + bcolors.ENDC)
    LDAPSCAN = f"nmap ---script ldap* -p {port} -oN {dirs}{ip_address}/service_scans/ldap_{ip_address}.nmap {ip_address}"
    #print(bcolors.HEADER + LDAPSCAN + bcolors.ENDC)
    ldap_results = subprocess.getoutput(LDAPSCAN)
    print(bcolors.OKGREEN + "INFO: Finished with LDAP-scan for " + ip_address + bcolors.ENDC)
    write_to_file(ip_address, "ldap", ldap_results)
    #print(results_ldap)
    return


def kerbEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting KERBEROS basd scan on " + ip_address + ":" + port + bcolors.ENDC)
    KERBSCAN = f'DOM=$(nmap -p 88 --script krb5-enum-users {ip_address} | grep report | cut -d " " -f 5) && nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=$DOM {ip_address} -oN {dirs}{ip_address}/service_scans/kerberos_{ip_address}.nmap {ip_address}'
    #print(bcolors.HEADER + KERBSCAN + bcolors.ENDC)
    kerb_results = subprocess.getoutput(KERBSCAN)
    print(bcolors.OKGREEN + "INFO: Finished with KERBEROS-scan for " + ip_address + bcolors.ENDC)
    write_to_file(ip_address, "kerb", kerb_results)
    #print(results_kerb)
    return


def nfsEnum(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting NFS based scan on " + ip_address + bcolors.ENDC)
    SHOWMOUNT = f"showmount -e {ip_address} | tee {dirs}{ip_address}/service_scans/nfs_{ip_address}.nmap"
    #print(bcolors.HEADER + SHOWMOUNT + bcolors.ENDC)
    nfsscan_results = subprocess.getoutput(SHOWMOUNT)
    print(bcolors.OKGREEN + "INFO: Finished with NFS-scan for " + ip_address + bcolors.ENDC)
    #print(nfsscan_results)
    write_to_file(ip_address, "nfsscan", nfsscan_results)
    return


def sshScan(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting SSH based scan on " + ip_address + ":" + port + bcolors.ENDC)
    connect_to_port(ip_address, port, "ssh")
    ssh_process = multiprocessing.Process(target=sshBrute, args=(ip_address, port))
    ssh_process.start()
    return


def sshBrute(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting SSH Bruteforce on " + ip_address + ":" + port + bcolors.ENDC)
    SSHSCAN = f"sudo hydra -I -C /opt/doubletap-git/wordlists/quick_hit.txt  -t 3 ssh://{ip_address} -s {port} | grep target"
    results_ssh = subprocess.getoutput(SSHSCAN)  # 
    print(bcolors.OKGREEN + "INFO: Finished with SSH-Bruteforce check for " + ip_address + bcolors.ENDC)
    # print results_ssh
    write_to_file(ip_address, "sshscan", results_ssh)
    return


def pop3Scan(ip_address, port):
    print(bcolors.HEADER + "INFO: Starting POP3 scan on " + ip_address + ":" + port + bcolors.ENDC)
    connect_to_port(ip_address, port, "pop3")
    return


def vulnEnum(ip_address, port):
    print(bcolors.OKGREEN + "INFO: Running Vulnerability based nmap scans for " + ip_address + bcolors.ENDC)
    VULN = f"nmap -sV --script=vuln --script-timeout=600 -p {ports} {ip_address} -oN {dirs}{ip_address}/port_scans/vuln_{ip_address}.nmap"
    vuln_results = subprocess.getoutput(VULN)
    print(bcolors.OKGREEN + "INFO: Finished with VULN-scan for " + ip_address + bcolors.ENDC)
    #print(vuln_results)
    write_to_file(ip_address, "vulnscan", vuln_results)
    return


def tcpScan(ip_address):
    print(bcolors.OKBLUE + "INFO: Running FULL TCP nmap scan on " + ip_address + bcolors.ENDC)
    # TCPALL = "unicornscan -p a %s | tee %s%s/port_scans/fulltcp_%s.nmap" % (ip_address, dirs, ip_address, ip_address)
    TCPALL = f"nmap -sV -Pn -p1-65535 --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 {ip_address} | tee {dirs}{ip_address}/port_scans/fulltcp_{ip_address}.nmap"
    tcp_results = subprocess.getoutput(TCPALL)
    print(bcolors.OKGREEN + "INFO: Finished with FULL-TCP-scan for " + ip_address + bcolors.ENDC)
    #print(tcp_results)
    write_to_file(ip_address, "fulltcpscan", tcp_results)
    return


def udpScan(ip_address):
    print(bcolors.OKBLUE + "INFO: Running UDP nmap scan on " + ip_address + bcolors.ENDC)
    UDPSCAN = f"nmap -Pn -A -sC -sU -T 4 --top-ports 200 -oN {dirs}{ip_address}/port_scans/udp_{ip_address}.nmap {ip_address}"
    udpscan_results = subprocess.getoutput(UDPSCAN)
    print(bcolors.OKGREEN + "INFO: Finished with UDP-scan for " + ip_address + bcolors.ENDC)
    #print(udpscan_results)
    write_to_file(ip_address, "udpscan", udpscan_results)
    return


# takes output directly from unicornscan
# returns a dict of protocols and the port they run on
def parseUn(result:str)->dict:
    port_protocol = {}
    lines = result.split("\n")
    for line in lines:
        ports = [];
        port = 0;
        protocol = "";
        tokens = line.split(" ")
        for t in tokens:
            if "[" in t:
                protocol = t.split("[")[0]
            elif "]" in t:
                port = int(t.split("]")[0])
        if protocol in port_protocol:
            # add to the list of ports in the dict
            port_protocol[protocol].append(port)
        else:
            # initialize a list for that protocol
            ports.append(port)
            port_protocol[protocol] = ports

    return port_protocol


def unicornTcpScan(ip_address, q):
    print(bcolors.OKGREEN + f"INFO: Running Full Unicornscan on {ip_address}, this may take a few mintues" + bcolors.ENDC)
    TCPALL = f"sudo unicornscan -mT {ip_address}:a | tee {ip_address}{dirs}/port_scans/fulltcp_{ip_address}.uni"
    open_ports = subprocess.getoutput(TCPALL)
    print(bcolors.OKGREEN + "INFO: Finished with FULL-TCP-scan for " + ip_address + bcolors.ENDC)
    #print(open_ports)
    write_to_file(ip_address, "fulltcpscan", open_ports)
    ports_dirty = ",".join(re.findall('\[(.*?)\]', open_ports))
    clean_ports = ports_dirty.replace(' ', '')
    q.put((parseUn(open_ports), clean_ports)) # returning a tuple for the two different purposes
    return


def vulnEnumForUni(ip_address: str ,ports: str):
    if not ports.strip(" "):
        print("{bcolors.FAIL}\nNo ports open for nmap vulnscan\n {bcolors.ENDC}") 
        return
    print(bcolors.OKGREEN + "INFO: Running Vulnerability based nmap scans for " + ip_address + bcolors.ENDC)
    VULN = f"nmap -sV --script=vuln --script-timeout=600 -p {ports} {ip_address} -oN {dirs}{ip_address}/port_scans/vuln_{ip_address}.nmap"
    vuln_results = subprocess.getoutput(VULN)
    print(bcolors.OKGREEN + "INFO: Finished with VULN-scan for " + ip_address + bcolors.ENDC)
    #print(vuln_results)
    write_to_file(ip_address, "vulnscan", vuln_results)
    return


resultQueue = multiprocessing.Queue()
# Starting funtion to parse and pipe to multiprocessing
def portScan(ip_address, unicornscan, resultQueue):
    ip_address = ip_address.strip()
    print("")
    print(bcolors.OKGREEN + "INFO: Current default output directory set as " + bcolors.ENDC + dirs)
    print(bcolors.OKGREEN + "INFO: Host IP set as " + bcolors.ENDC + myip)
    print("")
    
    if(unicornscan):
        # do the full unicornscan stuff
        m = multiprocessing.Process(target=unicornTcpScan, args=(scanip,resultQueue,))
        m.start()
        # get unicornScan output tuple, queue is used in case we want to add udp scan as well
        tcp_output = resultQueue.get()
        # run targeted nmap on the open ports
        l = multiprocessing.Process(target=vulnEnumForUni, args=(scanip, tcp_output[1],))
        l.start()
        serv_dict = tcp_output[0]
    else:
        # use nmap top 1000 to generate quick list and do more complete scans
        l = multiprocessing.Process(target=udpScan, args=(scanip,))
        l.start()
        m = multiprocessing.Process(target=tcpScan, args=(scanip,))
        m.start()
        print(bcolors.OKBLUE + "INFO: Running Quick TCP nmap scans for " + ip_address + bcolors.ENDC)
        TCPSCAN = f"nmap -sV -Pn --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 --top-ports 1000 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"
        #TCPSCAN = f"nmap -sV -Pn -p1-65535 --max-retries 1 --max-scan-delay 10 --defeat-rst-ratelimit --open -T4 --top-ports 1000 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"
        #TCPSCAN = f"nmap -sV -Pn -O --top-ports 100 {ip_address} -oN {dirs}{ip_address}/port_scans/{ip_address}.nmap"
        results = subprocess.getoutput(TCPSCAN)
        #print(results)      
        print(bcolors.OKGREEN + "INFO: Finished with QUICK-TCP-scan for " + ip_address + bcolors.ENDC)
        #print(results)
        
        #    write_to_file(ip_address, "portscan", results)
        lines = results.split("\n")
        serv_dict = {}
        for line in lines:
            ports = []
            line = line.strip()
            if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
                # print line
                while "  " in line:
                    line = line.replace("  ", " ");
                linesplit = line.split(" ")
                service = linesplit[2]  # grab the service name

                port = line.split(" ")[0]  # grab the port/proto
                # print port
                if service in serv_dict:
                    ports = serv_dict[service]  # if the service is already in the dict, grab the port list

                ports.append(port)
                # print ports
                serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)
                #print(bcolors.OKBLUE)
                #print("Scanning the follwoing service scans:")
                #print(bcolors.HEADER)
                #print(serv_dict)
                #print(bcolors.ENDC)
                #print("Found the following ports open:\n" + ports)

    # Search through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]
        if (serv == "http") or (serv == "http-proxy") or (serv == "http-alt") or (serv == "http?") or (
                serv == "http-proxy?"):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif (serv == "ssl/http") or ("https" == serv) or ("https?" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpsEnum, ip_address, port)
        elif "smtp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(smtpEnum, ip_address, port)
        elif "ftp" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ftpEnum, ip_address, port)
        elif ("microsoft-ds" in serv) or ("netbios-ssn" == serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(smbEnum, ip_address, port)
                multProc(rpcEnum, ip_address, port)
                multProc(samrEnum, ip_address, port)
        elif "ms-sql" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(mssqlEnum, ip_address, port)
        elif "rpcbind" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(nfsEnum, ip_address, port)
        elif "ssh" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(sshScan, ip_address, port)
        elif "ldap" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(ldapEnum, ip_address, port)                
        elif "kerberos-sec" in serv:
            for port in ports:
                port = port.split("/")[0]
                multProc(kerbEnum, ip_address, port)   
    return


# PSA's
print(bcolors.HEADER)
print("------------------------------------------------------------")
print("!!!!                     DOUBLETAP                     !!!!!")
print("!!!!                A script kiddies delite            !!!!!")
print("!!!!  An all in one recon and target template creator  !!!!!")
print("!!!!            Automagically runs the following       !!!!!")
print("!!!!     gobuster, nikto, ftp, ssh, mssql, pop3, tcp   !!!!!")
print("!!!!           udp, smtp, smb, wig, hydra              !!!!!")
print("------------------------------------------------------------")

if not os.geteuid()==0:
    sys.exit('This script must be run with sudo!')
elif len(sys.argv) < 2:
    print("")
    print("Usage: python3 doubletap.py -t <ip> <ip> -i <interface> -o /home/Desktop/")
    print("Example: python doubletap.py -t 192.168.1.101 192.168.1.102 -i tun0")
    print("Current default output directory set as " + default_dirs)
    print("Host IP set as " + myip)
    print("")
    sys.exit()

print(bcolors.ENDC)


parser = argparse.ArgumentParser()

#-t target(s) -n -o ~/Desktop -i eth:0
parser.add_argument("-t", "--target(s)", dest = "targets", default = "", help="IP address of target(s) separated by spaces")
parser.add_argument("-u", "--unicorn", dest = "unicorn", action="store_true", help="use unicornscan instead of nmap")
parser.add_argument("-o", "--output",dest ="output", help="absolute filepath to output dir")
parser.add_argument("-i", "--interface",dest = "interface", help="interface to use, default is eth0")


args = parser.parse_args()

if args.output:
    dirs = args.output
else:
    dirs = "/home/" + str(os.environ["SUDO_USER"]) + "/Desktop/"

if args.interface:
    myip = ni.ifaddresses(args.interface)[ni.AF_INET][0]['addr']
else:
    myip = ni.ifaddresses("eth0")[ni.AF_INET][0]['addr']

if args.unicorn:
    unicorn = True
else:
    unicorn = False

# Main start and folder creation
if __name__ == '__main__':

    # Setting ip targets
    targets = args.targets.split(" ")

    for scanip in targets:
        scanip = scanip.rstrip()
        if not scanip in subprocess.getoutput(f"ls {dirs}"):
            print(bcolors.HEADER + "INFO: No folder was found for " + scanip + ". Setting up folder the folder " + dirs + scanip + bcolors.ENDC)
            subprocess.getoutput("mkdir " + dirs + scanip)
            subprocess.getoutput("mkdir " + dirs + scanip + "/exploits")
            subprocess.getoutput("mkdir " + dirs + scanip + "/privesc")
            subprocess.getoutput("mkdir " + dirs + scanip + "/service_scans")
            subprocess.getoutput("mkdir " + dirs + scanip + "/webapp_scans")
            subprocess.getoutput("mkdir " + dirs + scanip + "/port_scans")

            print(bcolors.OKGREEN + "INFO: Folder created here: " + dirs + scanip + bcolors.ENDC)

            subprocess.getoutput("cp /opt/doubletap-git/templates/windows-template.md " + dirs + scanip + "/" + scanip + "-windows-exploit-steps.md")
            subprocess.getoutput("cp /opt/doubletap-git/templates/linux-template.md " + dirs + scanip + "/" + scanip + "-linux-exploit-steps.md")
            subprocess.getoutput("cp /opt/doubletap-git/templates/windows-worksheet-template.md " + dirs + scanip + "/" + scanip + "-windows-notes.md")
            subprocess.getoutput("cp /opt/doubletap-git/templates/linux-worksheet-template.md " + dirs + scanip + "/" + scanip + "-linux-notes.md")

            print(bcolors.OKGREEN + "INFO: Added pentesting templates to: " + dirs + scanip + bcolors.ENDC)

            subprocess.getoutput("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' " + dirs + scanip + "/" + scanip + "-windows-exploit-steps.md")
            subprocess.getoutput("sed -i -e 's/MYIPADDRESS/" + myip + "/g' " + dirs + scanip + "/" + scanip + "-windows-exploit-steps.md")
            subprocess.getoutput("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' " + dirs + scanip + "/" + scanip + "-linux-exploit-steps.md")
            subprocess.getoutput("sed -i -e 's/MYIPADDRESS/" + myip + "/g' " + dirs + scanip + "/" + scanip + "-linux-exploit-steps.md")

        p = multiprocessing.Process(target=portScan, args=(scanip,unicorn,resultQueue))
        time.sleep(1)  # Just a nice wait for unicornscan
        p.start()
