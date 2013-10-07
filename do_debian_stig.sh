#!/bin/bash
# File: do_debian_stig.sh
#
# Author: Jeffrey Malnick jpmalnic@nps.edu
# Funding Agency: CORE Lab, Naval Postgraduate School
# Creation Date: 21 March 2013
#
# Revision: 1.1
# Revision Date: 24 March 2013
# Revision Author: Jeffrey Malnick
# 
# ***********************************************************************************
#
# No Copyright, open source script for DoD debian systems users. Free to distribute
# No confidential or proprietary information is contained within this scirpt.
#
# ***********************************************************************************
#
# This is a STIG script intended for use on Debian Linux systems and will patch 
# level 1 and level 2 STIG offences for a base-line stock Debian install. Development
# of this scirpt was done on Ubuntu 10.04 - 12.04LTS and is intended mainly for
# those OS's. 
#
# ***********************************************************************************
#
# Requires: Ubuntu 10.04 or later && the latest Python libs
#
# Comments: Only level 1 and 2 STIG offences will be patched. Please contact the 
# script author for issues with this script.
#
# ***********************************************************************************
# ***********************************************************************************
#
# Set user message of the day with current DoD IA Banner and STIG conformance message
# This queries the local intranet 172.20** server for a recent banner. Places that MOTD in a file /usr/bin/motd.txt
# It then creates a script to be ran before the login screen that the user must accept via xmessaging window queried by lightdm
# Note: This only works with lightDM; a seperate script to query display manager (GDM or LightDM) will need to be developed. 
# TODO: Check for display manager type and add a GDM banner if using GDM in lieu of LightDM
echo "Getting message of the day"
rsync 172.20.40.119::motd-data/motd /usr/bin/motd.txt
echo "installing motd.sh script at /usr/bin/motd.sh"
echo "#!/bin/bash ; xmessage -file /usr/bin/motd.txt" > /usr/bin/motd.sh
chmod a+x motd.sh
echo "display-setup-script=/usr/bin/motd.sh" >> /etc/lightdm/lightdm.conf
echo /usr/bin/motd.txt 
echo "has been installed on login screen"


# Initialize log in /tmp/STIG_log.txt
rm /tmp/STIG_log.txt

echo "File: do_debian_stig.sh" >> /tmp/STIG_log.txt
echo "Funding Agency: CORE Lab, Naval Postgraduate School" >> /tmp/STIG_log.txt
echo "Creation Date: 21 March 2013" >> /tmp/STIG_log.txt
echo "Revision: 1.1" >> /tmp/STIG_log.txt
echo "Revision Date: 21 March 2013" >> /tmp/STIG_log.txt
echo "Author: Jeffrey Malnick jpmalnic@nps.edu" >> /tmp/STIG_log.txt

# Make sure you have Python installed because I'm to lazy to compare floats in Shell..
pythonvar=`dpkg -s python | grep Version`
if [ `echo "$pythonvar" | cut -d: -f1` = version ]
then echo "Python installed, moving on."
else echo "Python not installed, installing..."
	sudo apt-get --force-yes --yes install python
	echo "#####################################################" >> /tmp/STIG_log.txt
	echo "Installed the latest version of Python" >> /tmp/STIG_log.txt
	echo "#####################################################" >> /tmp/STIG_log.txt
fi

# OpenSSL DTLS CVE-2012-2333 Remote Denial of Service Vulnerability
# Audit ID 53476
# Upgrade OpenSSL to version 0.9.8x, 1.0.0j, 1.0.1c, or newer if needed
#!/bin/sh
echo "Getting SSL version"
echo "OpenSSL remote DoS Vulnerability:" >> /tmp/STIG_log.txt
echo "SSL Upgrade Check:"
sslconstant=1
sslversion=`dpkg -s openssl | grep Version | cut -d. -f1 | cut -d: -f2`
echo $sslversion
if [ "$sslversion" -lt "$sslconstant" ]
        then
		echo "Which is not 1.0.x or greater, updating"
        	sudo apt-get --force-yes --yes update
        	echo "OpenSSL DTLS CVE-2012-2333 Remote Denial of Service Vulnerability was found" >> /tmp/STIG_log.txt
			sudo apt-get --force-yes --yes install openssl
	# Check that the OS supports SSL v1.0x or later...
	sslversion2=`dpkg -s openssl | grep Version | cut -d. -f1 | cut -d: -f2`
	if [ "$sslversion2" -le "$sslconstant" ]
		then
			echo "Unable to download SSL version 1.0x or greater, your OS does not support it" >> /tmp/STIG_log.txt
			echo "Please update your OS or find a suitable patch for OpenSSL" >> /tmp/STIG_log.txt
   			echo "The current version of SSL is not supported by your OS, please see /tmp/STIG_log.txt for updating"
		else
			echo "SSL is now up to date." >> /tmp/STIG_log.txt
	fi
	else
		echo "SSL is verion 1.0.x or greater, no need to update"
		echo "Your version of SSL is up to date, did not need to update" >> /tmp/STIG_log.txt
fi
echo "#####################################################" >> /tmp/STIG_log.txt
# Sudo Netmask Bypass Privilege Escalation (20120522)
# Audit ID 16471
# Upgrade Sudo to version 1.8.4p5, 1.7.9p1, or newer; or upgrade vendor-specific packages to the appropriate backported fixed release.
echo "Sudo Netmask Bypass Privilege Escalation (20120522)"
echo "Checking sudo version and upgrading if neccessary"
echo "Sudo netmask bypass privledge escalation:" >> /tmp/STIG_log.txt
sudoversion=`dpkg -s sudo | grep Version | cut -d: -f2`
export sudotest=1.8
echo "Running sudo version: " $sudoversion | cut -d. -f1,2
export sudovar=`echo $sudoversion | cut -d. -f1,2`
echo $sudovar "is the sudovar"
python - $sudovar $sudotest <<EOF
import sys
print 'Variables Passed', ' '.join(sys.argv[1:])
if $sudovar >= $sudotest:
        print('Sudo is up to date')
        i=1
else:
        print('Sudo needs to be updated')
        i=0
sys.exit(i)
EOF

echo "sudo value:" $?
if [ "$?" -eq 1 ]
then 
	echo "Nothing to do."
	echo "Your version of sudo is up to date, no sudo update was made" >> /tmp/STIG_log.txt
else 
	echo "Updating sudo..."
	echo "Your version of sudo was out of date, it was updated" >> /tmp/STIG_log.txt
	sudo apt-get --force-yes --yes install sudo
fi
echo "Finished updating sudo."
echo "#####################################################" >> /tmp/STIG_log.txt

# SSH Security Login Issue
# Audit ID 7415
# Disable remote root logins in sshd_config and setting "PermitRootLogin" to "no".
echo "Testing for SSH root login privledges..."
echo "SSH root login privledge check: " >> /tmp/STIG_log.txt
sshvar=`cat /etc/ssh/sshd_config | grep PermitRootLogin | cut -d' ' -f2`
echo "Allow Root Login?:" $sshvar 
if [ ! "$sshvar" = "yes" ] 
	then 
		echo "Root Login is Permitted, changing to NOT permitted" 
		echo "Root login was found to be permitted, this has been disabled: sed -i -e s/PermitRootLogin yes/PermitRootLogin no/" >> /tmp/STIG_log.txt
		sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
elif [ ! "$sshVar" = "no"]
	then
		echo "Root Login is not permitted, moving on..."
		echo "Root login was found to not be permitted, thank you." >> /tmp/STIG_log.txt
else 
	echo "SSH Daemon (sshd) is not currently configured, moving on..."
	echo "The SSH daemon (sshd) is not currently configured on your system, nothing was done." >> /tmp/STIG_log.txt
fi			
echo "#####################################################" >> /tmp/STIG_log.txt

# A heap overflow vulnerability exists within rsync version 2.5.7 and prior 
# Audit ID 2526
# Get rsync version and compare, ensure version is greater than 2.6
echo "Testing rsync version for heap overflow vulnerability" 
echo "Rsync version heap overflow vulnerability:" >> /tmp/STIG_log.txt
rsync=`dpkg -s rsync | grep Version | cut -d: -f2`
export rsyncvar=2.6
export rsynctest=`echo $rsync | cut -d. -f1,2`

python - $rsyncvar $rsynctest <<EOF
import sys
print 'Variables Passed', ' '.join(sys.argv[1:])
if $rsynctest >= $rsyncvar:
        print('True: your rsync is up to date')
        i=1
else:
        print('False: your rsync needs to be updated')
        i=0
sys.exit(i)
EOF

if [ "$?" -eq 1 ]
then 
	echo "Nothing to do."
	echo "Rsync was found to be up to date, nothing was done." >> /tmp/STIG_log.txt
else 
	echo "Updating rsync..."
	echo "Rsync was not up to date, it was updated" >> /tmp/STIG_log.txt
	sudo apt-get --force-yes --yes install rsync
fi
echo "Finished updating rsync."
echo "#####################################################" >> /tmp/STIG_log.txt

# ICMP Timestamp Patch
# Audit ID 3688
# Filter or block ICMP Timestamp (Type 13) requests on the target using a host-based firewall

echo "TODO: implement patch"

######################################

echo "Doing misc. security stuff your sys admin should have done already..." 
# Set root ownership for /etc/security
echo "Set root ownership for /etc/security" >> /tmp/STIG_log.txt
echo "Fixing ownership of /etc/security"
touch /etc/security/opasswd
chown root:root /etc/security/opasswd
chmod 0600 /etc/security/opasswd
echo "Done."

# Set sticky bit, give root full permission at /root, remove group permission at /root and remove global permission at /root

chmod 0700 /root
echo "Gave root full permission at /root" >> /tmp/STIG_log.txt

# Test for access control (ACL), install if needed, remove all /root
sudo apt-get --force-yes --yes install acl
echo "Installed access control lists (ACL)" >> /tmp/STIG_log.txt
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' acl "install ok installed")
echo Checking for acl: $PKG_OK
if [ "" == "$PKG_OK" ]; then
  echo "No Access Conrol Lists Installed; Setting up ACL"
  sudo apt-get --force-yes --yes install acl
fi

setfacl --remove-all /root

# ACL settings and root ownership for NAC and NIC files
 
files="/etc/resolv.conf /etc/hosts /etc/nsswitch.conf /etc/passwd /etc/group /etc/skel/*"
for file in $files
do
   echo $file "was given root:root and 0644 permissions" >> /tmp/STIG_log.txt
   chown root:root $file
   chmod 0644 $file
   setfacl --remove-all $file
done
echo "Debian hardening complete, cheers" >> /tmp/STIG_log.txt
echo "Complete." 














