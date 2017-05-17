#!/bin/bash
####################################################################################################################

#incorporate brad's signatures in to signatures/cross, remove andromedia/dridex_apis/chimera_api/deletes_self/cryptowall_apis


if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit 1
fi
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
gitdir=$PWD

##Logging setup
logfile=/var/log/cuckoo_install.log
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
########################################
##BEGIN MAIN SCRIPT##
#Pre checks: These are a couple of basic sanity checks the script does before proceeding.
##Depos add
#this is a nice little hack I found in stack exchange to suppress messages during package installation.
export DEBIAN_FRONTEND=noninteractive
#/etc/apt/apt.conf.d/10periodic
#APT::Periodic::Update-Package-Lists "0";
##Cuckoo user accounts
echo -e "${YELLOW}We need to create a local account to run your Cuckoo sandbox from; What would you like your Cuckoo account username to be?${NC}"
read name
adduser $name --gecos ""
echo -e "${YELLOW}Please type in a MySQL root password${NC}"
read root_mysql_pass
echo -e "${YELLOW}Please type in a MySQL cuckoo password${NC}"
read cuckoo_mysql_pass

for iface in $(ifconfig | cut -d ' ' -f1| tr '\n' ' ')
do 
  addr=$(ip -o -4 addr list $iface | awk '{print $4}' | cut -d/ -f1)
  printf "$iface\t$addr\n"
done

echo -e "${YELLOW}What is the name of the interface you wish to route traffic through?(ex: eth0)${NC}"
read interface
echo -e "${YELLOW}If you want to use Snort, please type in your Oinkcode, if you do not have it now you will need to append it to /etc/snort/pulledpork.conf in the future, the cron job will take care of updating it.${NC}"
read oinkcode

##Create directories and scripts for later
cd /home/$name/
dir=$PWD
dir_check /home/$name/tools
dir_check /home/$name/conf
dir_check /home/$name/Sources
sed -i 's/interface = ens33/interface = "$interface"/g' $gitdir/conf/routing.conf &>> $logfile
cp $gitdir/conf/* /home/$name/conf
cp $gitdir/lib/40-permissions.rules /etc/udev/rules.d/40-permissions.rules
cp $gitdir/supporting_scripts/firstrun.sh /home/$name/
cp $gitdir/lib/yara/*.yar /home/$name/
chmod +x  $gitdir/supporting_scripts/rooter.sh
cp $gitdir/supporting_scripts/rooter.sh ~/
cp $gitdir/supporting_scripts/update_signatures.sh ~/
chown $name:$name -R /home/$name/conf
chown $name:$name -R /home/$name/firstrun.sh
chmod +x /home/$name/firstrun.sh
#rm -rf /home/$name/tools/*
chmod +x $gitdir/supporting_scripts/start_cuckoo.sh
chown $name:$name $gitdir/supporting_scripts/start_cuckoo.sh
cp $gitdir/supporting_scripts/start_cuckoo.sh /home/$name/
cd tools/

###Add Repos
install_packages python-software-properties software-properties-common
##Mongodb
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 0C49F3730359A14518585931BC711F9BA15703C6 &>> $logfile
echo "deb [ arch=amd64,arm64 ] http://repo.mongodb.org/apt/ubuntu xenial/mongodb-org/3.4 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-3.4.list &>> $logfile
error_check 'Mongodb repo added'

##Java
add-apt-repository ppa:webupd8team/java -y &>> $logfile
error_check 'Java repo added'

##Elasticsearch
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - &>> $logfile
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | tee /etc/apt/sources.list.d/elasticsearch-2.x.list &>> $logfile
error_check 'Elasticsearch repo added'

##Suricata
add-apt-repository ppa:oisf/suricata-beta -y &>> $logfile
error_check 'Suricata repo added'

####End of repos
##Holding pattern for dpkg...
print_status "${YELLOW}Waiting for dpkg process to free up...${NC}"
print_status "${YELLOW}If this takes too long try running ${RED}sudo rm -f /var/lib/dpkg/lock${YELLOW} in another terminal window.${NC}"
while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
   sleep 1
done

### System updates
print_status "${YELLOW}Performing apt-get update and upgrade (May take a while if this is a fresh install)..${NC}"
apt-get update &>> $logfile && apt-get -y dist-upgrade &>> $logfile
error_check 'Updated system'

##Main Packages
print_status "${YELLOW}Downloading and installing depos${NC}"
apt-get install -y build-essential checkinstall &>> $logfile
chmod u+rwx /usr/local/src &>> $logfile
apt-get install -y linux-headers-$(uname -r) &>> $logfile
install_packages  python   python-dev	python-pip	python-setuptools	python-sqlalchemy	python-virtualenv xfce4 xfce4-goodies vim firefox  make	automake	libdumbnet-dev	libarchive-dev	libcap2-bin	libconfig-dev	libcrypt-ssleay-perl	libelf-dev	libffi-dev	libfuzzy-dev	libgeoip-dev	libjansson-dev	libjpeg-dev	liblwp-useragent-determined-perl	liblzma-dev	libmagic-dev	libpcap-dev	libpcre++-dev	libpq-dev	libssl-dev	libtool	apparmor-utils	apt-listchanges	bison	byacc	clamav	clamav-daemon	clamav-freshclam	dh-autoreconf	elasticsearch	fail2ban	flex	gcc	mongodb-org	suricata	swig	tcpdump	tesseract-ocr	unattended-upgrades	uthash-dev	zlib1g-dev	wkhtmltopdf	xvfb	xfonts-100dpi	libstdc++6:i386	libgcc1:i386	zlib1g:i386	libncurses5:i386	subversion	build-essential	bcc	iasl	xsltproc	uuid-dev	libidl-dev	libsdl1.2-dev	libxcursor-dev	libasound2-dev	libstdc++5	libpulse-dev	libxml2-dev	libxslt1-dev	pyqt5-dev-tools	libqt5opengl5-dev	qtbase5-dev-tools	libcap-dev	libxmu-dev	mesa-common-dev	libglu1-mesa-dev	linux-libc-dev	libcurl4-openssl-dev	libpam0g-dev	libxrandr-dev	libxinerama-dev	makeself	libdevmapper-dev	default-jdk	texlive-latex-base	texlive-latex-extra	texlive-latex-recommended	texlive-fonts-extra	texlive-fonts-recommended	lib32ncurses5	lib32z1	libc6-dev-i386	lib32gcc1	gcc-multilib	lib32stdc++6	g++-multilib	genisoimage	libvpx-dev	qt5-default	qttools5-dev-tools	libqt5x11extras5-dev	python-all-dev
error_check 'Depos installed'
