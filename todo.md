Install script checks

Create VMs in virtualbox first, DO NOT START
  -2 cores / 2GB RAM / PIX3 / NO PAENX / Legacy para / 256GB HDD / enable audio / host onlyif
  - Create hardware profile with antivmdetect using config_example.sh
  - Run setup scripts within folder to change hardware profiles using virtualboxsetup.sh
Start VM and install Windows
  -Turn off updates
  -Turn off firewall
  -Apply Win key
  -Run ninite
  -Install agent and add to startup reg
  -Install PIL
  
Switch to host only interface

Restart
  -Configure network
  -Join domain
Restart
  -SMB map
  -run PS1 script on host
Restart
  -run PS1 script again

  

  
  
