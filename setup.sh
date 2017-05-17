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
echo
echo -e "${YELLOW}Active interfaces${NC}"
for iface in $(ifconfig | cut -d ' ' -f1| tr '\n' ' ')
do 
  addr=$(ip -o -4 addr list $iface | awk '{print $4}' | cut -d/ -f1)
  printf "$iface\t$addr\n"
done
echo
echo -e "${YELLOW}What is the name of the interface you wish to route traffic through?(ex: eth0)${NC}"
read interface
echo -e "${YELLOW}If you want to use Snort, please type in your Oinkcode, if you do not have it now you will need to append it to /etc/snort/pulledpork.conf in the future, the cron job will take care of updating it.${NC}"
read oinkcode

##Create directories and scripts for later
cd /home/$name/
dir=$PWD
dir_check /home/$name/tools
dir_check /home/$name/conf
dir_check /home/$name/sources
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

##Cloaked VirtualBox
print_status "${YELLOW}Installing VirtualBox...this will take about 10-20 minutes.${NC}"/
cd /home/$name/sources/
svn co http://www.virtualbox.org/svn/vbox vbox  &>> $logfile
# Directories and filenames
SOURCESDIR=/home/$name/sources/vbox/trunk                 # Dir where the vbox source code is
KMKTOOLSSUBDIR=kBuild/bin/linux.amd64                   # where we find the kmk tools e.g. kmk_md5sum
MD5SUMOUT=$SOURCESDIR/kmk_md5.out                   # log md5sum ops to this file
VBOXMANAGE=$SOURCESDIR/out/linux.amd64/release/bin/VXoxManage       # location and name of VBoxManage binary (after renamed)
# Suspicious strings to rename e.g. "VirtualBox" gets renamed to "XirtualXox" (no spaces, same length!)
VirtualBox=XirtualXox
virtualbox=xirtualxox
VIRTUALBOX=XIRTUALXOX
virtualBox=xirtualXox
vbox=vxox
Vbox=Vxox
VBox=VXox
VBOX=VXOX
Oracle=Xracle
oracle=xracle
innotek=xnnotek
InnoTek=XnnoTek
INNOTEK=XNNOTEK
PCI80EE=80EF
PCI80ee=80ef

# Logging some stuff of the installation to...
vlogfile="$(basename -s ".sh" $0).out"

me="$(basename $0)"
count=0
# Rename files and folders arg1=string in filename to search for, arg2=string to rename filename to
function rename_files_and_dirs {
    print_notification "[*]Replacing string \"$1\" to \"$2\" in all filenames"
    a=0
    false
    while [ $? -ne 0 ]; do a=`expr $a + 1`;
        find . -name "*$1*" ! -name $me ! -name $vlogfile -exec bash -c "mv \"\$0\" \"\${0/$1/$2}\"" {} \;
    done;
}

function replace_strings {
    count=`expr $count + 1`
    print_notification -n "$count/15 "
    print_notification "[*]Replacing string \"$1\" with string \"$2\" in all files. Be patient this takes a while (~35sec on my box)..."
    find . -type f ! -name $me ! -name $vlogfile -exec sed -i "s/$1/$2/g" {} +
}

print_notification "[*]This scripts is patching the vbox souce code, compiles it and finally installs the VirtualBox application"


if [ -d $SOURCESDIR ]; then
        cd $SOURCESDIR
else
    print_notification "[ERROR]Did you changed the variables (see above)? SOURCEDIR does not exist. Aborting"
    exit 1
fi

if [ ! -f configure ] || [ ! -f Maintenance.kmk ]; then
    print_notification "[ERROR]You are in the wrong directory. Aborting..."
    exit 1
fi


    _echo "[*]Start configuring the source code."
    ./configure --disable-hardening 
    source $SOURCESDIR/env.sh


    print_notification "[*]Start compiling the org. source code. That takes a while. Get a coffee..."
    kmk 



    print_notification "[*] Compiling the org. kernel modules"
    cd $SOURCESDIR/out/linux.amd64/release/bin/src/
    make 


    print_notification "[*] Fixing access rights and cleaning up"
    cd $SOURCESDIR
    source ./env.sh
    kmk clean
    sudo chown -R $USER:$(id -gn) *
    sudo chown -R $USER:$(id -gn) .*


    print_notification "[*]Renaming files"
    # Rename files and folders
    rename_files_and_dirs VirtualBox $VirtualBox
    rename_files_and_dirs virtualbox $virtualbox
    rename_files_and_dirs vbox $vbox
    rename_files_and_dirs VBox $VBox
    rename_files_and_dirs Oracle $Oracle
    rename_files_and_dirs oracle $oracle


    print_notification "[*]Starting string replacment. All 15 rounds are taking approx. 10min on my box, so go and get a coffee"
    replace_strings VirtualBox $VirtualBox
    replace_strings virtualbox $virtualbox
    replace_strings VIRTUALBOX $VIRTUALBOX
    replace_strings virtualBox $virtualBox
    replace_strings vbox $vbox
    replace_strings Vbox $Vbox
    replace_strings VBox $VBox
    replace_strings VBOX $VBOX
    replace_strings Oracle $Oracle
    replace_strings oracle $oracle
    replace_strings innotek $innotek
    replace_strings InnoTek $InnoTek
    replace_strings INNOTEK $INNOTEK
    replace_strings 80EE $PCI80EE
    replace_strings 80ee $PCI80ee


    print_notification "[*]Replacing BIOS date"
    sed -i 's/06\/23\/99/07\/24\/13/g' $SOURCESDIR/src/VXox/Devices/PC/BIOS/orgs.asm


    print_notification "[*]Configuring source code"
    ./configure --disable-hardening 
    source $SOURCESDIR/env.sh
    replace_strings QVXoxLayout QVBoxLayout


    print_notification "[*]Replacing kmk_md5 tools with our version to fix MAKE's BIOS check"
    if [ -e "$SOURCESDIR/$KMKTOOLSSUBDIR/kmk_md5sum" ]; then
        mv $SOURCESDIR/$KMKTOOLSSUBDIR/kmk_md5sum $SOURCESDIR/$KMKTOOLSSUBDIR/kmk_md5sum.bak
        cat > $SOURCESDIR/$KMKTOOLSSUBDIR/kmk_md5sum <<- EOF
        #!/bin/bash
        echo \$2 >>$MD5SUMOUT
        echo \$2
        echo
EOF
        chmod +x $SOURCESDIR/$KMKTOOLSSUBDIR/kmk_md5sum
    else
        print_notification "[ERROR] File \"$SOURCESDIR/$KMKTOOLSSUBDIR/kmk_md5sum\" not found"
        exit 1
    fi


    print_notification "[*]Start compiling source code. That takes a while. Get a coffee..."
    kmk >&3


    print_notification "[*]Patching BIOS date in autom. generated files"
    print_notification "[*]File: out/linux.amd64/release/obj/PcBiosBin/PcBiosBin286.c"
    sed -i 's/06\.23\.99/07\.24\.13/g' $SOURCESDIR/out/linux.amd64/release/obj/PcBiosBin/PcBiosBin286.c
    sed -i 's/0x30\, 0x36\, 0x2f\, 0x32\, 0x33\, 0x2f\, 0x39\, 0x39/0x30\, 0x37\, 0x2f\, 0x32\, 0x34\, 0x2f\, 0x31\, 0x32/g' out/linux.amd64/release/obj/PcBiosBin/PcBiosBin286.c >&3

    print_notification "[*]File: out/linux.amd64/release/obj/PcBiosBin/PcBiosBin386.c"
    sed -i 's/06\.23\.99/07\.24\.13/g' $SOURCESDIR/out/linux.amd64/release/obj/PcBiosBin/PcBiosBin386.c
    sed -i 's/0x30\, 0x36\, 0x2f\, 0x32\, 0x33\, 0x2f\, 0x39\, 0x39/0x30\, 0x37\, 0x2f\, 0x32\, 0x34\, 0x2f\, 0x31\, 0x32/g' out/linux.amd64/release/obj/PcBiosBin/PcBiosBin386.c >&3

    print_notification "[*]File: out/linux.amd64/release/obj/PcBiosBin/PcBiosBin8086.c"
    sed -i 's/06\.23\.99/07\.24\.13/g' $SOURCESDIR/out/linux.amd64/release/obj/PcBiosBin/PcBiosBin8086.c
    sed -i 's/0x30\, 0x36\, 0x2f\, 0x32\, 0x33\, 0x2f\, 0x39\, 0x39/0x30\, 0x37\, 0x2f\, 0x32\, 0x34\, 0x2f\, 0x31\, 0x32/g' out/linux.amd64/release/obj/PcBiosBin/PcBiosBin8086.c >&3

    print_notification "[*] Compiling BIOS files again."
    kmk >&3


    print_notification "[*] Compiling kernel modules"
    cd $SOURCESDIR/out/linux.amd64/release/bin/src/
    make


    print_notification "[*] Installing kernel modules"
    sudo make install


print_notification "[*]Compiling source code is done."


# -------- Installing Virtual Box ---------


cd $SOURCESDIR/out/linux.amd64/release/bin

# Take care of kernel modules
if [ "$(lsmod | grep vxox)" ]; then
    print_notification "[*] vxox kernel modules already loaded. Unloading them..."
    sudo rmmod vxoxpci
    sudo rmmod vxoxnetflt
    sudo rmmod vxoxnetadp
    sudo rmmod vxoxdrv
fi

print_notification "[*] Loading vxox kernel modules"
sudo modprobe vxoxdrv
sudo modprobe vxoxnetflt
sudo modprobe vxoxnetadp
sudo modprobe vxoxpci

print_notification "[*] Following modules loaded:"
lsmod | grep vxox

    print_notification "[*] Adding modules to /etc/modules"
    echo 'vxoxdrv'    | sudo tee --append /etc/modules > /dev/null
    echo 'vxoxpci'    | sudo tee --append /etc/modules > /dev/null
    echo 'vxoxnetadp' | sudo tee --append /etc/modules > /dev/null
    echo 'vxoxnetflt' | sudo tee --append /etc/modules > /dev/null


# Copying files to usr dir

    if [ -e "/usr/local/virtualbox" ]; then
        print_notification "Deleting old /usr/local/virtualbox folder"
        sudo rm -rf /usr/local/virtualbox
    fi
    
    sudo mkdir /usr/local/virtualbox
    print_notification "Copying binaries to /usr/local/virtualbox"
    sudo cp -prf $SOURCESDIR/out/linux.amd64/release/bin/*    /usr/local/virtualbox/
    print_notification "Copying shared libraries to /usr/lib/"
    sudo cp -prf $SOURCESDIR/out/linux.amd64/release/bin/*.so /usr/lib/
    print_notification "Creating some symlinks to e.g. XirtualXox to VirtualBox"
    if [ ! -e "/usr/local/bin/VirtualBox" ]; then sudo ln -s /usr/local/virtualbox/XirtualXox  /usr/local/bin/VirtualBox; fi
    if [ ! -e "/usr/local/bin/VBoxSVC"    ]; then sudo ln -s /usr/local/virtualbox/VXoxSVC     /usr/local/bin/VBoxSVC;    fi
    if [ ! -e "/usr/local/bin/VBoxManage" ]; then sudo ln -s /usr/local/virtualbox/VXoxManage  /usr/local/bin/VBoxManage; fi


    if [ -e "/etc/udev/rules.d/40-permissions.rules" ]; then
        sudo cp /etc/udev/rules.d/40-permissions.rules /etc/udev/rules.d/40-permissions.rules.vboxinstaller.bak
    else
        mkdir /etc/udev/rules.d/40-permissions.rules
    fi

    print_notification "[*]Adding devices in /etc/udev/rules.d/40-permissions.rules"
    echo 'KERNEL=="vxoxdrv",                        GROUP="vboxusers", MODE="0660"' \
        | sudo tee --append /etc/udev/rules.d/40-permissions.rules > /dev/null
    echo 'KERNEL=="vxoxdrv",                        GROUP="vboxusers", MODE="0660"' \
        | sudo tee --append /etc/udev/rules.d/40-permissions.rules > /dev/null
    echo 'KERNEL=="vxoxdrvu",                       GROUP="vboxusers", MODE="0660"' \
        | sudo tee --append /etc/udev/rules.d/40-permissions.rules > /dev/null


groupadd vboxusers
usermod -G vboxusers -a $name
chmod 660 /dev/vxox*
chgrp vboxusers /dev/vxox*
VBoxManage hostonlyif create 
echo "auto vxoxnet0"
echo "iface vxoxnet0 inet static" | sudo tee -a /etc/network/interfaces
echo "address         10.1.1.254" | sudo tee -a /etc/network/interfaces
echo "netmask         255.255.255.0" | sudo tee -a /etc/network/interfaces
echo "network         10.1.1.0" | sudo tee -a /etc/network/interfaces
echo "broadcast       10.1.1.255" | sudo tee -a /etc/network/interfaces
error_check 'Virtualbox installed and setup for Cuckoo'

##Cuckoo
print_status "${YELLOW}Downloading and installing Cuckoo and Python dependencies${NC}"
pip install -U pip setuptools &>> $logfile
pip install -U pip flex &>> $logfile
pip install -U pip distorm3 &>> $logfile
pip install -U pip pycrypto &>> $logfile
pip install -U pip weasyprint &>> $logfile
pip install -U pip yara-python &>> $logfile
pip install -U pip cuckoo &>> $logfile
error_check 'Cuckoo downloaded and installed'

##Java install for elasticsearch
print_status "${YELLOW}Installing Java${NC}"
echo debconf shared/accepted-oracle-license-v1-1 select true | \
  sudo debconf-set-selections &>> $logfile
apt-get install oracle-java7-installer -y &>> $logfile
error_check 'Java Installed'

##Start mongodb 
print_status "${YELLOW}Setting up MongoDB${NC}"
chmod 755 $gitdir/lib/mongodb.service &>> $logfile
cp $gitdir/lib/mongodb.service /etc/systemd/system/ &>> $logfile
systemctl start mongodb &>> $logfile
systemctl enable mongodb &>> $logfile
error_check 'MongoDB Setup'

##Setup Elasticsearch
print_status "${YELLOW}Setting up Elasticsearch${NC}"
systemctl daemon-reload &>> $logfile
systemctl enable elasticsearch.service &>> $logfile
systemctl start elasticsearch.service &>> $logfile
error_check 'Elasticsearch Setup'

##Yara
cd /home/$name/tools/
print_status "${YELLOW}Downloading Yara${NC}"
#wget https://github.com/VirusTotal/yara/archive/v3.5.0.tar.gz &>> $logfile
git clone https://github.com/VirusTotal/yara.git &>> $logfile
error_check 'Yara downloaded'
#tar -zxf v3.5.0.tar.gz &>> $logfile
print_status "${YELLOW}Building and compiling Yara${NC}"
#cd yara-3.5.0
cd yara/
./bootstrap.sh &>> $logfile
./configure --with-crypto --enable-cuckoo --enable-magic &>> $logfile
error_check 'Yara compiled and built'
print_status "${YELLOW}Installing Yara${NC}"
make &>> $logfile
make install &>> $logfile
make check &>> $logfile
error_check 'Yara installed'

##DTrace
print_status "${YELLOW}Downloading and installing DTrace${NC}"
cd /etc
git clone https://github.com/dtrace4linux/linux.git dtrace &>> $logfile
cd dtrace
bash tools/get-deps.pl -y &>> $logfile
make all &>> $logfile
make install &>> $logfile
make load &>> $logfile
error_check 'DTrace installed'

##Pydeep
cd /home/$name/tools/
print_status "${YELLOW}Setting up Pydeep${NC}"
sudo -H pip install git+https://github.com/kbandla/pydeep.git &>> $logfile
error_check 'Pydeep installed'

##Malheur
#cd /home/$name/tools/
#print_status "${YELLOW}Setting up Malheur${NC}"
#git clone https://github.com/rieck/malheur.git &>> $logfile
#error_check 'Malheur downloaded'
#cd malheur
#./bootstrap &>> $logfile
#./configure --prefix=/usr &>> $logfile
#make install &>> $logfile
#error_check 'Malheur installed'

##Volatility
cd /home/$name/tools/
print_status "${YELLOW}Setting up Volatility${NC}"
wget https://github.com/volatilityfoundation/volatility/archive/2.6.zip &>> $logfile
error_check 'Volatility downloaded'
unzip 2.6.zip &>> $logfile
cd volatility-2.6 &>> $logfile
python setup.py build &>> $logfile
python setup.py install &>> $logfile
error_check 'Volatility installed'

##MITMProxy
print_status "${YELLOW}Installing MITM${NC}"
apt-get install python3-dev python3-pip libffi-dev libssl-dev -y &>> $logfile
pip3 install mitmproxy &>> $logfile
error_check 'MITM installed'

##Suricata
cd /home/$name/tools/
print_status "${YELLOW}Setting up Suricata${NC}"
touch /etc/suricata/rules/cuckoo.rules &>> $logfile
echo "alert http any any -> any any (msg:\"FILE store all\"; filestore; noalert; sid:15; rev:1;)"  | sudo tee /etc/suricata/rules/cuckoo.rules &>> $logfile
chown $name:$name /etc/suricata/suricata.yaml

##etupdate
git clone https://github.com/seanthegeek/etupdate &>> $logfile
cd etupdate
mv etupdate /usr/sbin/
/usr/sbin/etupdate -V &>> $logfile
error_check 'Suricata updateded'
chown $name:$name /usr/sbin/etupdate &>> $logfile
chown -R $name:$name /etc/suricata/rules &>> $logfile
crontab -u $name $gitdir/lib/cron  
cp $gitdir/lib/suricata-cuckoo.yaml /etc/suricata/suricata.yaml
error_check 'Suricata configured for auto-update'

##Snort
print_status "${YELLOW}Setting up Snort${NC}"
cd $gitdir/
wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz &>> $logfile
tar -zxvf daq-2.0.6.tar.gz &>> $logfile
cd daq*  &>> $logfile
./configure &>> $logfile
make  &>> $logfile
make install  &>> $logfile
error_check 'DAQ installed'
cd $gitdir
wget https://www.snort.org/downloads/snort/snort-2.9.9.0.tar.gz  &>> $logfile
tar -xvzf snort-2.9.9.0.tar.gz  &>> $logfile
cd snort*
./configure --enable-sourcefire &>> $logfile
make &>> $logfile
make install  &>> $logfile
error_check 'Snort installed'
ldconfig  &>> $logfile
ln -s /usr/local/bin/snort /usr/sbin/snort  &>> $logfile
groupadd snort  &>> $logfile 
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort  &>> $logfile
mkdir -p /etc/snort/rules/iplists  &>> $logfile
mkdir /etc/snort/preproc_rules &>> $logfile
mkdir /usr/local/lib/snort_dynamicrules &>> $logfile
mkdir /etc/snort/so_rules &>> $logfile
mkdir -p /var/log/snort/archived_logs &>> $logfile
touch /etc/snort/rules/iplists/black_list.rules &>> $logfile
touch /etc/snort/rules/iplists/white_list.rules &>> $logfile
touch /etc/snort/rules/local.rules &>> $logfile
touch /etc/snort/rules/snort.rules &>> $logfile
touch /etc/snort/sid-msg.map &>> $logfile
chmod -R 5775 /etc/snort &>> $logfile
chmod -R 5775 /var/log/snort &>> $logfile
chmod -R 5775 /usr/local/lib/snort_dynamicrules &>> $logfile
chown -R snort:snort /etc/snort &>> $logfile
chown -R $name:$name /var/log/snort &>> $logfile
chown -R snort:snort /usr/local/lib/snort_dynamicrules &>> $logfile
cd $gitdir/snort-*/etc/ &>> $logfile
cp *.conf* /etc/snort &>> $logfile
cp *.map /etc/snort &>> $logfile
cp *.dtd /etc/snort &>> $logfile
cd $gitdir/snort-*/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/ &>> $logfile
cp * /usr/local/lib/snort_dynamicpreprocessor/ &>> $logfile
cp $gitdir/lib/snort.conf /etc/snort/ &>> $logfile

##Pulledpork
cd $gitdir
git clone https://github.com/shirkdog/pulledpork.git &>> $logfile
cd pulledpork &>> $logfile
sudo cp pulledpork.pl /usr/local/bin/ &>> $logfile
chmod +x /usr/local/bin/pulledpork.pl &>> $logfile
cp etc/*.conf /etc/snort/ &>> $logfile
cp $gitdir/lib/pulledpork.conf /etc/snort/ &>> $logfile
sed -ie "s/<oinkcode>/$oinkcode/g" /etc/snort/pulledpork.conf
/usr/local/bin/pulledpork.pl -c /etc/snort/pulledpork.conf -l &>> $logfile
cp  $gitdir/lib/snort.service /lib/systemd/system/ &>> $logfile
systemctl enable snort &>> $logfile
systemctl start snort &>> $logfile
error_check 'Pulledpork installed'

##MySQL install
print_status "${YELLOW}Installing MySQL${NC}"
debconf-set-selections <<< "mysql-server mysql-server/$root_mysql_pass password root" &>> $logfile
debconf-set-selections <<< "mysql-server mysql-server/$root_mysql_pass password root" &>> $logfile
error_check 'MySQL passwords set' 
print_status "${YELLOW}Downloading and installing MySQL${NC}"
apt-get -y install mysql-server python-mysqldb &>> $logfile 
error_check 'MySQL installed'
print_status "${YELLOW}Configuring MySQL${NC}"
mysql -uroot -p$root_mysql_pass -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; DROP DATABASE IF EXISTS cuckoo; CREATE DATABASE cuckoo; GRANT ALL PRIVILEGES ON cuckoo.* TO 'cuckoo'@'localhost' IDENTIFIED BY '$cuckoo_mysql_pass'; FLUSH PRIVILEGES;" &>> $logfile
#mysql -uroot -p$root_mysql_pass -e "DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; DROP DATABASE IF EXISTS cuckoo; FLUSH PRIVILEGES;" &>> $logfile
error_check 'MySQL secure installation and cuckoo database/user creation'
replace "connection =" "connection = mysql://cuckoo:$cuckoo_mysql_pass@localhost/cuckoo" -- /home/$name/conf/cuckoo.conf &>> $logfile
error_check 'Configuration files modified'



##Other tools
cd /home/$name/tools/
print_status "${YELLOW}Grabbing other tools${NC}"
install_packages libboost-all-dev
sudo -H pip install git+https://github.com/buffer/pyv8 &>> $logfile
print_status "${YELLOW}Installing antivmdetect and tools${NC}"
##Folder setup
dir_check /usr/bin/cd-drive
##Antivm download
cp $gitdir/lib/Ninite* $PWD
git clone https://github.com/benrau87/antivmdetect.git
git clone https://github.com/benrau87/vboxhardening.git
error_check 'Antivm tools downloaded'

##Holding pattern for dpkg...
print_status "${YELLOW}Waiting for dpkg process to free up...${NC}"
print_status "${YELLOW}If this takes too long try running ${RED}sudo rm -f /var/lib/dpkg/lock${YELLOW} in another terminal window.${NC}"
while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
   sleep 1
done

##Permissions
print_status "${YELLOW}Setting tcpdump vbox permissions${NC}"
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump &>> $logfile
aa-disable /usr/sbin/tcpdump &>> $logfile
error_check 'Permissions set'

###Setup of VirtualBox forwarding rules and host only adapter
#print_status "${YELLOW}Creating virtual adapter${NC}"
#iptables -t nat -A POSTROUTING -o $interface -s 10.1.1.0/24 -j MASQUERADE &>> $logfile
#iptables -P FORWARD DROP &>> $logfile
#iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT &>> $logfile
#iptables -A FORWARD -s 10.1.1.0/24 -j ACCEPT &>> $logfile
#iptables -A FORWARD -s 10.1.1.0/24 -d 10.1.1.0/24 -j ACCEPT &>> $logfile
#iptables -A FORWARD -j LOG &>> $logfile
echo 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward &>> $logfile
sysctl -w net.ipv4.ip_forward=1 &>> $logfile
#print_status "${YELLOW}Preserving Iptables${NC}"
#apt-get -qq install iptables-persistent -y &>> $logfile
#error_check 'Persistent Iptable entries'

##Rooter
print_status "${YELLOW}Adding route commands and crons${NC}"
echo "400    $interface" | tee -a /etc/iproute2/rt_tables &>> $logfile
systemctl enable rc-local &>> $logfile
cp $gitdir/lib/threshold.config /etc/suricata/
error_check "Commands Added, please restart to finish installation"

echo -e "${YELLOW}Installation complete, login as $name and open the terminal. Run the cuckoo command in the terminal to finish setup. Now copy the conf file in your ~ directory to ~/.cuckoo/conf/. In $name home folder you will find the start_cuckoo script. To get started as fast as possible you will need to create a virtualbox vm and name it ${RED}cuckoo1${NC}.${YELLOW} On the Windows VM install the windows_exes that can be found under the tools folder. Name the snapshot ${RED}vmcloak${YELLOW}. Alternatively you can create the VM with the vmcloak.sh script provided in your home directory. This will require you have a local copy of the Windows ISO you wish to use. You can then launch cuckoo_start.sh and navigate to $HOSTNAME:8000 or https://$HOSTNAME if Nginx was installed.${NC}"

