#!/bin/bash

echo ""
echo "****************************************"
echo "PcapPlusPlus Linux configuration script "
echo "****************************************"
echo ""

# set Script Name variable
SCRIPT=`basename ${BASH_SOURCE[0]}`

# help function
function HELP {
   echo -e \\n"Help documentation for ${SCRIPT}."\\n
   echo "This script has 2 modes of operation:"
   echo "  1) Without any switches. In this case the script will guide you through using wizards"
   echo "  2) With switches, as described below"
   echo ""
   echo -e "Basic usage: $SCRIPT [-h] [--pf-ring] [--pf-ring-home] [--dpdk] [--dpdk-home] [--use-immediate-mode] [--install-dir] [--libpcap-include-dir] [--libpcap-lib-dir]"\\n
   echo "The following switches are recognized:"
   echo "--default             --Setup PcapPlusPlus for Linux without PF_RING or DPDK. In this case you must not set --pf-ring or --dpdk"
   echo ""
   echo "--pf-ring             --Setup PcapPlusPlus with PF_RING. In this case you must also set --pf-ring-home"
   echo "--pf-ring-home        --Sets PF_RING home directory. Use only when --pf-ring is set"
   echo ""
   echo "--dpdk                --Setup PcapPlusPlus with DPDK. In this case you must also set --dpdk-home"
   echo "--dpdk-home           --Sets DPDK home directoy. Use only when --dpdk is set"
   echo ""
   echo "--use-immediate-mode  --Use libpcap immediate mode which enables getting packets as fast as possible (supported on libpcap>=1.5)"
   echo ""
   echo "--install-dir         --Installation directory. Default is /usr/local"
   echo ""
   echo "--libpcap-include-dir --libpcap header files directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "                        the header files in the default include paths"
   echo "--libpcap-lib-dir     --libpcap pre compiled lib directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "                        the lib file in the default lib paths"
   echo ""
   echo -e "-h|--help             --Displays this help message and exits. No further actions are performed"\\n
   echo -e "Examples:"
   echo -e "      $SCRIPT --default"
   echo -e "      $SCRIPT --use-immediate-mode"
   echo -e "      $SCRIPT --libpcap-include-dir /home/myuser/my-libpcap/include --libpcap-lib-dir /home/myuser/my-libpcap/lib"
   echo -e "      $SCRIPT --install-dir /home/myuser/my-install-dir"
   echo -e "      $SCRIPT --pf-ring --pf-ring-home /home/myuser/PF_RING"
   echo -e "      $SCRIPT --dpdk --dpdk-home /home/myuser/dpdk-2.1.0"
   echo ""
   exit 1
}

# initializing PF_RING variables
COMPILE_WITH_PF_RING=0
PF_RING_HOME=""

# initializing DPDK variables
COMPILE_WITH_DPDK=0
DPDK_HOME=""
HAS_PCAP_IMMEDIATE_MODE=0

# initializing libpcap include/lib dirs to an empty string 
LIBPCAP_INLCUDE_DIR=""
LIBPCAP_LIB_DIR=""

# default installation directory
INSTALL_DIR=/usr/local

#Check the number of arguments. If none are passed, continue to wizard mode.
NUMARGS=$#
echo -e "Number of arguments: $NUMARGS"\\n

# start wizard mode
if [ $NUMARGS -eq 0 ]; then

   # ask the user whether to compile with PF_RING. If so, set COMPILE_WITH_PF_RING to 1
   while true; do
      read -p "Compile PcapPlusPlus with PF_RING? " yn
      case $yn in
          [Yy]* ) COMPILE_WITH_PF_RING=1; break;;
          [Nn]* ) break;;
          * ) echo "Please answer yes or no";;
      esac
   done

   # if compiling with PF_RING, get PF_RING home dir from the user and set it in PF_RING_HOME
   if (( $COMPILE_WITH_PF_RING > 0 )) ; then
      while true; do # don't stop until user provides a valid dir
         read -e -p "Enter PF_RING source path: " PF_RING_HOME
         if [ -d "$PF_RING_HOME" ]; then
            break;
         else
            echo "Directory doesn't exist"
         fi
      done
   fi

   # ask the user whether to compile with DPDK. If so, set COMPILE_WITH_DPDK to 1
   while true; do
       read -p "Compile PcapPlusPlus with DPDK? " yn
       case $yn in
           [Yy]* ) COMPILE_WITH_DPDK=1; break;;
           [Nn]* ) break;;
           * ) echo "Please answer yes or no";;
       esac
   done

   # if compiling with DPDK, get DPDK home dir and set it in DPDK_HOME
   if (( $COMPILE_WITH_DPDK > 0 )) ; then
       while true; do # don't stop until user provides a valid dir
           read -e -p "Enter DPDK source path: " DPDK_HOME
           if [ -d "$DPDK_HOME" ]; then
               break;
           else
               echo "Directory doesn't exist"
           fi
       done
   fi

# script was run with parameters, go to param mode
else

   # these are all the possible switches
   OPTS=`getopt -o h --long default,pf-ring,pf-ring-home:,dpdk,dpdk-home:,help,use-immediate-mode,install-dir:,libpcap-include-dir:,libpcap-lib-dir: -- "$@"`

   # if user put an illegal switch - print HELP and exit
   if [ $? -ne 0 ]; then
      HELP
   fi

   eval set -- "$OPTS"

   # go over all switches
   while true ; do
     case "$1" in
       # default switch - do nothing basically
       --default)
         shift ;;

       # pf-ring switch - set COMPILE_WITH_PF_RING to 1
       --pf-ring)
         COMPILE_WITH_PF_RING=1
         shift ;;

       # pf-ring-home switch - set PF_RING_HOME and make sure it's a valid dir, otherwise exit
       --pf-ring-home)
         PF_RING_HOME=$2
         if [ ! -d "$PF_RING_HOME" ]; then
            echo "PG_RING home directory '$PF_RING_HOME' not found. Exiting..."
            exit 1
         fi
         shift 2 ;;

       # dpdk switch - set COMPILE_WITH_DPDK to 1
       --dpdk)
         COMPILE_WITH_DPDK=1
         shift 1 ;;

       # dpdk-home switch - set DPDK_HOME and make sure it's a valid dir, otherwise exit
       --dpdk-home)
         DPDK_HOME=$2
         if [ ! -d "$DPDK_HOME" ]; then
            echo "DPDK home directory '$DPDK_HOME' not found. Exiting..."
            exit 1
         fi
         shift 2 ;;

       # enable libpcap immediate mode
       --use-immediate-mode)
         HAS_PCAP_IMMEDIATE_MODE=1
         shift ;;

       # non-default libpcap include dir
       --libpcap-include-dir)
         LIBPCAP_INLCUDE_DIR=$2
         shift 2 ;;

       # non-default libpcap lib dir
       --libpcap-lib-dir)
         LIBPCAP_LIB_DIR=$2
         shift 2 ;;

       # installation directory prefix
       --install-dir)
         INSTALL_DIR=$2
         if [ ! -d "$INSTALL_DIR" ]; then
            echo "Installation directory '$INSTALL_DIR' not found. Exiting..."
            exit 1
         fi
         shift 2 ;;

       # help switch - display help and exit
       -h|--help)
         HELP
         ;;

       # empty switch - just go on
       --)
         shift ; break ;;

       # illegal switch
       *)
         echo -e \\n"Option -$OPTARG not allowed."
         HELP
         ;;
     esac
   done

   # if --pf-ring was set, make sure --pf-ring-home was also set, otherwise exit with error
   if [[ $COMPILE_WITH_PF_RING > 0 && $PF_RING_HOME == "" ]]; then
      echo "Switch --pf-ring-home wasn't set. Exiting..."
      exit 1
   fi

   # if --dpdk was set, make sure --dpdk-home is also set, otherwise exit with error
   if [[ $COMPILE_WITH_DPDK > 0 && $DPDK_HOME == "" ]] ; then
      echo "Switch --dpdk-home wasn't set. Exiting..."
      exit 1
   fi

   ### End getopts code ###
fi


PLATFORM_MK="mk/platform.mk"
PCAPPLUSPLUS_MK="mk/PcapPlusPlus.mk"

# copy the basic Linux platform.mk
cp -f mk/platform.mk.linux $PLATFORM_MK

# copy the common (all platforms) PcapPlusPlus.mk
cp -f mk/PcapPlusPlus.mk.common $PCAPPLUSPLUS_MK

# add the Linux definitions to PcapPlusPlus.mk
cat mk/PcapPlusPlus.mk.linux >> $PCAPPLUSPLUS_MK

# set current directory as PCAPPLUSPLUS_HOME in platform.mk
echo -e "\n\nPCAPPLUSPLUS_HOME := "$PWD >> $PLATFORM_MK

# set current direcrtory as PCAPPLUSPLUS_HOME in PcapPlusPlus.mk (write it in the first line of the file)
sed -i "1s|^|PCAPPLUSPLUS_HOME := $PWD\n\n|" $PCAPPLUSPLUS_MK

# if compiling with PF_RING
if (( $COMPILE_WITH_PF_RING > 0 )) ; then

   # add PF_RING definitions to PcapPlusPlus.mk
   cat mk/PcapPlusPlus.mk.pf_ring >> $PCAPPLUSPLUS_MK

   # set PF_RING_HOME variable in platform.mk
   echo -e "\n\nPF_RING_HOME := "$PF_RING_HOME >> $PLATFORM_MK

   # set PF_RING_HOME variable in PcapPlusPlus.mk (write it in the second line of the file)
   sed -i "2s|^|PF_RING_HOME := $PF_RING_HOME\n\n|" $PCAPPLUSPLUS_MK
fi


# function to extract DPDK major + minor version from <DPDK_HOM>/pkg/dpdk.spec file
# return: DPDK version (major + minor only)
function get_dpdk_version() {
   echo $(grep "Version" $DPDK_HOME/pkg/dpdk.spec | cut -d' ' -f2 | cut -d'.' -f 1,2)
}

# function to compare between 2 versions (each constructed of major + minor)
# param1: first version to compare
# param2: second version to compate
# return: 1 if first>=second, 0 otherwise
function compare_versions() {
   echo "$1 $2" | awk '{if ($1 >= $2) print 1; else print 0}'
}

# if compiling with DPDK
if (( $COMPILE_WITH_DPDK > 0 )) ; then

   # add DPDK definitions to PcapPlusPlus.mk
   cat mk/PcapPlusPlus.mk.dpdk >> $PCAPPLUSPLUS_MK

   # if DPDK ver >= 17.11 concat additional definitions to PcapPlusPlus.mk
   CUR_DPDK_VERSION=$(get_dpdk_version)
   if [ "$(compare_versions $CUR_DPDK_VERSION 17.11)" -eq "1" ] ; then
      cat mk/PcapPlusPlus.mk.dpdk_new >> $PCAPPLUSPLUS_MK
   fi

   # set USE_DPDK variable in platform.mk
   echo -e "\n\nUSE_DPDK := 1" >> $PLATFORM_MK

   # set DPDK home to RTE_SDK variable in platform.mk
   echo -e "\n\nRTE_SDK := "$DPDK_HOME >> $PLATFORM_MK

   # set USE_DPDK varaible in PcapPlusPlus.mk
   sed -i "2s|^|USE_DPDK := 1\n\n|" $PCAPPLUSPLUS_MK

   # set DPDK home to RTE_SDK variable in PcapPlusPlus.mk
   sed -i "2s|^|RTE_SDK := $DPDK_HOME\n\n|" $PCAPPLUSPLUS_MK

   # set the setup-dpdk script:

   # copy the initial version to PcapPlusPlus root dir
   cp mk/setup-dpdk.sh.template setup-dpdk.sh

   # make it an executable
   chmod +x setup-dpdk.sh

   # replace the RTE_SDK placeholder with DPDK home
   sed -i "s|###RTE_SDK###|$DPDK_HOME|g" setup-dpdk.sh

fi

if (( $HAS_PCAP_IMMEDIATE_MODE > 0 )) ; then
   echo -e "HAS_PCAP_IMMEDIATE_MODE := 1\n\n" >> $PCAPPLUSPLUS_MK
fi

# non-default libpcap include dir
if [ -n "$LIBPCAP_INLCUDE_DIR" ]; then
   echo -e "# non-default libpcap include dir" >> $PCAPPLUSPLUS_MK
   echo -e "LIBPCAP_INLCUDE_DIR := $LIBPCAP_INLCUDE_DIR" >> $PCAPPLUSPLUS_MK
   echo -e "PCAPPP_INCLUDES += -I\$(LIBPCAP_INLCUDE_DIR)\n" >> $PCAPPLUSPLUS_MK
fi

# non-default libpcap lib dir
if [ -n "$LIBPCAP_LIB_DIR" ]; then
   echo -e "# non-default libpcap lib dir" >> $PCAPPLUSPLUS_MK
   echo -e "LIBPCAP_LIB_DIR := $LIBPCAP_LIB_DIR" >> $PCAPPLUSPLUS_MK
   echo -e "PCAPPP_LIBS_DIR += -L\$(LIBPCAP_LIB_DIR)\n" >> $PCAPPLUSPLUS_MK
fi

# generate installation and uninstallation scripts
cp mk/install.sh.template mk/install.sh
sed -i.bak "s|{{INSTALL_DIR}}|$INSTALL_DIR|g" mk/install.sh && rm mk/install.sh.bak
chmod +x mk/install.sh

cp mk/uninstall.sh.template mk/uninstall.sh
sed -i.bak "s|{{INSTALL_DIR}}|$INSTALL_DIR|g" mk/uninstall.sh && rm mk/uninstall.sh.bak
chmod +x mk/install.sh


# finished setup script
echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK, mk/install.sh, mk/uninstall.sh"
