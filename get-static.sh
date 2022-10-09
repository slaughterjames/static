#!/bin/bash -
#===============================================================================
#Static v0.3 - Copyright 2022 James Slaughter,
#This file is part of Static v0.3.

#Static v0.3 is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#Static v0.3 is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with Static v0.3.  If not, see <http://www.gnu.org/licenses/>/>.
#===============================================================================
#------------------------------------------------------------------------------
#
# Install Static on top of an Ubuntu-based Linux distribution.
#
#------------------------------------------------------------------------------

__ScriptVersion="Static-v0.3-1"
LOGFILE="/var/log/static-install.log"
DIR="/opt/static/"
MODULES_DIR="/opt/static/modules/"
YARA_DIR="/opt/static/yara/"
OLEDUMP_DIR="/opt/oledump/"

echoerror() {
    printf "${RC} * ERROR${EC}: $@\n" 1>&2;
}

echoinfo() {
    printf "${GC} * INFO${EC}: %s\n" "$@";
}

echowarn() {
    printf "${YC} * WARN${EC}: %s\n" "$@";
}

__apt_get_install_noinput() {
    sudo apt-get install -y -o DPkg::Options::=--force-confold $@; return $?
}

__apt_get_upgrade_noinput() {
    sudo apt-get upgrade -y -o DPkg::Options::=--force-confold $@; return $?
}

__pip_install_noinput() {
    pip3 install --upgrade $@; return $?
}


usage() {
    echo "usage"
    exit 1
}


install_ubuntu_deps() {

  echoinfo "Updating the base APT repository package list... "
  apt-get update >> $LOGFILE 2>&1

  echoinfo "Upgrading all APT packages to latest versions..."
  __apt_get_upgrade_noinput >> $LOGFILE 2>&1

  ldconfig
  return 0
}

install_ubuntu_packages() {
    #Ubuntu packages that need to be installed
    packages="python3
    python3-pip
    yara
    curl
    lsb-release
    lnkinfo"

    if [ "$@" = "dev" ]; then
        packages="$packages"
    elif [ "$@" = "stable" ]; then
        packages="$packages"
    fi

    for PACKAGE in $packages; do
        echoinfo "Installing APT Package: $PACKAGE"
        __apt_get_install_noinput $PACKAGE >> $LOGFILE 2>&1
        ERROR=$?
    done
    
    return 0
}

install_pip_packages() {
  #Python Libraries that need to be installed
  pip_packages="termcolor
  oletools
  requests
  pefile
  peutils
  datetime
  vtapi3
  extract_msg
  email"

  if [ "$@" = "dev" ]; then
    pip_packages="$pip_packages"
  elif [ "$@" = "stable" ]; then
    pip_packages="$pip_packages"
  fi

  for PACKAGE in $pip_packages; do
    CURRENT_ERROR=0
    echoinfo "Installing Python Package: $PACKAGE"
    __pip_install_noinput $PACKAGE >> $LOGFILE 2>&1 || (let ERROR=ERROR+1 && let CURRENT_ERROR=1)
    if [ "$CURRENT_ERROR" -eq 1 ]; then
      echoerror "Python Package Install Failure: $PACKAGE"
    fi
  done

  return 0
}

install_static_package() {
  #Pull Static from GitHub, unzip and install it
  echoinfo "Installing Static"
  wget -q "https://github.com/slaughterjames/static/archive/refs/heads/main.zip" --output-document "/tmp/main.zip"
  unzip -q "/tmp/main.zip" -d "/tmp/"
  chmod -R 755 "/tmp/static-main/" 
  mv "/tmp/static-main"/* "$DIR" 
  rm -R "/tmp/static-main/"
  rm "/tmp/main.zip"

  return 0
}

install_secondary_packages() {
  #Pull ViperMonkey Docker script
  echoinfo "***NOTE*** Docker is a prerequisite to use the Vipermonkey module for Static!!!"
  echoinfo "Updating dockermonkey"
  wget -q wget "https://raw.githubusercontent.com/decalage2/ViperMonkey/master/docker/dockermonkey.sh" --output-document "/tmp/dockermonkey.sh"
  chmod 755 "/tmp/dockermonkey.sh"
  mv "/tmp/dockermonkey.sh" "$DIR"

  #Pull Yara from GitHub, unzip and install it
  echoinfo "Updating Yara rules"
  wget -q "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip" --output-document "/tmp/master.zip"
  unzip -q "/tmp/master.zip" -d "/tmp/"
  chmod -R 755 "/tmp/rules-master/"
  cp -R "/tmp/rules-master"/* "$YARA_DIR"
  rm -R "/tmp/rules-master/"
  rm "/tmp/master.zip"

  #Pull oledump from Didier Stevens, unzip and install it
  echoinfo "Pulling oledump"
  wget -q "http://didierstevens.com/files/software/oledump_V0_0_70.zip" --output-document "/tmp/oledump_V0_0_70.zip"
  unzip -q "/tmp/oledump_V0_0_70.zip" -d "/tmp/oledump_V0_0_70"
  chmod -R 755 "/tmp/oledump_V0_0_70/"
  cp -R "/tmp/oledump_V0_0_70"/* "$OLEDUMP_DIR"
  rm -R "/tmp/oledump_V0_0_70/"
  rm "/tmp/oledump_V0_0_70.zip"



  return 0
}

configure_static() {
  #Creates the necessary directories for Static in /opt/static
  echoinfo "Creating directories"

  mkdir -p $DIR >> $LOGFILE 2>&1
  chmod -R 755 $DIR >> $LOGFILE 2>&1

  mkdir -p $MODULES_DIR >> $LOGFILE 2>&1
  chmod -R 755 $MODULES_DIR >> $LOGFILE 2>&1

  mkdir -p $YARA_DIR >> $LOGFILE 2>&1
  chmod -R 755 $YARA_DIR >> $LOGFILE 2>&1

  mkdir -p $OLEDUMP_DIR >> $LOGFILE 2>&1
  chmod -R 755 $OLEDUMP_DIR_DIR >> $LOGFILE 2>&1

  return 0
}

complete_message() {
    #Message that displays on completion of the process
    echoinfo "---------------------------------------------------------------"
    echoinfo "Static Installation Complete!"
    echoinfo "Reboot for the settings to take full effect (\"sudo reboot\")."
    echoinfo "---------------------------------------------------------------"

    return 0
}

#Grab the details about the system
OS=$(lsb_release -si)
ARCH=$(uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(lsb_release -sr)

#Print out details about the system
echo "Installing Static on: $OS"
echo "Architecture is: $ARCH bit"
echo "Version is: $VER"
echo ""

#Bail if installation isn't
if [ `whoami` != "root" ]; then
    echoerror "The Static installation script must run as root."
    echoerror "Usage: sudo ./get-static.sh"
    exit 3
fi

if [ "$SUDO_USER" = "" ]; then
    echoerror "The SUDO_USER variable doesn't seem to be set"
    exit 4
fi

while getopts ":hvnicu" opt
do
case "${opt}" in
    h ) echo "Usage:"
        echo ""
        echo "sudo ./get-static.sh [options]"
        echo ""
        exit 0
        ;;
    v ) echo "$0 -- Version $__ScriptVersion"; exit 0 ;;
    \?) echo ""
        echoerror "Option does not exist: $OPTARG"
        usage
        exit 1
        ;;
esac
done

shift $(($OPTIND-1))

if [ "$#" -eq 0 ]; then
    ITYPE="stable"
else
    __check_unparsed_options "$*"
    ITYPE=$1
    shift
fi

echo "---------------------------------------------------------------" >> $LOGFILE
echo "Running Static installer version $__ScriptVersion on `date`" >> $LOGFILE
echo "---------------------------------------------------------------" >> $LOGFILE

echoinfo "Installing Static. Details logged to $LOGFILE."

#Function calls
install_ubuntu_deps $ITYPE
install_ubuntu_packages $ITYPE
install_pip_packages $ITYPE
configure_static
install_static_package $ITYPE
install_secondary_packages $ITYPE
complete_message
