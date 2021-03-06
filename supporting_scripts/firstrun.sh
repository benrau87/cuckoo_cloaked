#!/bin/bash
cuckoo &
sleep 20
cuckoo community
mv clamavrules.yar ~/.cuckoo/yara/binaries/
mv clamavrules2.yar ~/.cuckoo/yara/binaries/
cd ~/.cuckoo/yara/
git clone https://github.com/yara-rules/rules.git 
cp rules/**/*.yar ~/.cuckoo/yara/binaries/
#cp ~/.mitmproxy/mitmproxy-ca-cert.p12 ~/.cuckoo/analyzer/windows/bin/cert.p12
cp ~/conf/* ~/.cuckoo/conf
##Remove Android and none working rules for now
rm ~/.cuckoo/yara/binaries/Android* 
rm ~/.cuckoo/yara/binaries/vmdetect.yar  
rm ~/.cuckoo/yara/binaries/antidebug_antivm.yar  
rm ~/.cuckoo/yara/binaries/MALW_AdGholas.yar  
rm ~/.cuckoo/yara/binaries/APT_Shamoon*.yar  
rm ~/.cuckoo/yara/binaries/peid.yar  



