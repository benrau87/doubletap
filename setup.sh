#!/bin/bash
####################################################################################################################


if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit 1
fi
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
gitdir=$PWD

##Logging setup
logfile=/var/log/target_install.log
mkfifo ${logfile}.pipe
tee < ${logfile}.pipe $logfile &
exec &> ${logfile}.pipe
rm ${logfile}.pipe

##Functions
function print_status ()
{
    echo -e "\x1B[01;34m[*]\x1B[0m $1"
}

function print_good ()
{
    echo -e "\x1B[01;32m[*]\x1B[0m $1"
}

function print_error ()
{
    echo -e "\x1B[01;31m[*]\x1B[0m $1"
}

function print_notification ()
{
	echo -e "\x1B[01;33m[*]\x1B[0m $1"
}

function error_check
{

if [ $? -eq 0 ]; then
	print_good "$1 successfully."
else
	print_error "$1 failed. Please check $logfile for more details."
exit 1
fi

}

function install_packages()
{

apt-get update &>> $logfile && apt-get install -y --allow-unauthenticated ${@} &>> $logfile
error_check 'Package installation completed'

}

function dir_check()
{

if [ ! -d $1 ]; then
	print_notification "$1 does not exist. Creating.."
	mkdir -p $1
else
	print_notification "$1 already exists. (No problem, We'll use it anyhow)"
fi

}

export DEBIAN_FRONTEND=noninteractive

########################################
##BEGIN MAIN SCRIPT##
print_notification Installing...

dir_check /opt/doubletap-git
cp -r $gitdir/* /opt/doubletap-git
chmod +x $gitdir/doubletap.py

pushd /opt/doubletap-git/ >/dev/null
#--- Add to path
mkdir -p /usr/local/bin/
file=/usr/local/bin/doubletap-git
cat <<EOF > "${file}" \
  || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/doubletap-git/ && python doubletap.py "\$@"
EOF
chmod +x "${file}"

git clone -q -b master  https://github.com/behindthefirewalls/Parsero.git /opt/parsero-git/ 
pushd /opt/parsero-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
mkdir -p /usr/local/bin/
file=/usr/local/bin/parsero-git
cat <<EOF > "${file}" \
  || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/parsero-git/ && python3 parsero.py "\$@"
EOF
chmod +x "${file}"

git clone -q -b master https://github.com/jekyc/wig.git /opt/wig-git/ 
pushd /opt/wig-git/ >/dev/null
git pull -q
popd >/dev/null
#--- Add to path
mkdir -p /usr/local/bin/
file=/usr/local/bin/wig-git
cat <<EOF > "${file}" \
  || echo -e ' '${RED}'[!] Issue with writing file'${RESET} 1>&2
#!/bin/bash
cd /opt/wig-git/ && python3 wig.py "\$@"
EOF
chmod +x "${file}"

git clone https://github.com/vulnersCom/nmap-vulners /tmp/vulners
cp /tmp/vulners/vulners.nse /usr/share/nmap/scripts

cd /usr/share/nmap/scripts/vulscan/
wget -N http://www.computec.ch/projekte/vulscan/download/cve.csv
wget -N http://www.computec.ch/projekte/vulscan/download/exploitdb.csv
wget -N http://www.computec.ch/projekte/vulscan/download/openvas.csv
wget -N http://www.computec.ch/projekte/vulscan/download/osvdb.csv
wget -N http://www.computec.ch/projekte/vulscan/download/scipvuldb.csv
wget -N http://www.computec.ch/projekte/vulscan/download/securityfocus.csv
wget -N http://www.computec.ch/projekte/vulscan/download/securitytracker.csv
wget -N http://www.computec.ch/projekte/vulscan/download/xforce.csv

nmap --script-updatedb

print_good Finished!



