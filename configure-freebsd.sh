#!/usr/local/bin/bash

echo ""
echo "*******************************************"
echo "PcapPlusPlus FreeBSD configuration script "
echo "*******************************************"
echo ""

# set Script Name variable
SCRIPT=`basename ${BASH_SOURCE[0]}`

# help function
function HELP {
   echo -e \\n"Help documentation for ${SCRIPT}."\\n
   echo -e "Basic usage: $SCRIPT [-h] [--use-immediate-mode] [--set-direction-enabled] [--install-dir] [--libpcap-include-dir] [--libpcap-lib-dir]"\\n
   echo "The following switches are recognized:"
   echo "--use-immediate-mode     --Use libpcap immediate mode which enables getting packets as fast as possible (supported on libpcap>=1.5)"
   echo ""
   echo "--set-direction-enabled  --Set direction for capturing incoming packets or outgoing packets (supported on libpcap>=0.9.1)"
   echo ""
   echo "--install-dir            --Set installation directory. Default is /usr/local"
   echo ""
   echo "--libpcap-include-dir    --libpcap header files directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "                           the header files in the default include paths"
   echo "--libpcap-lib-dir        --libpcap pre compiled lib directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "                           the lib file in the default lib paths"
   echo ""
   echo -e "-h|--help                --Displays this help message and exits. No further actions are performed"\\n
   echo -e "Examples:"
   echo -e "      $SCRIPT"
   echo -e "      $SCRIPT --use-immediate-mode"
   echo -e "      $SCRIPT --set-direction-enabled"
   echo -e "      $SCRIPT --libpcap-include-dir /home/myuser/my-libpcap/include --libpcap-lib-dir /home/myuser/my-libpcap/lib"
   echo -e "      $SCRIPT --install-dir /home/myuser/my-install-dir"
   echo ""
   exit 1
}

HAS_PCAP_IMMEDIATE_MODE=0
HAS_SET_DIRECTION_ENABLED=0

# initializing libpcap include/lib dirs to an empty string
LIBPCAP_INLCUDE_DIR=""
LIBPCAP_LIB_DIR=""

# default installation directory
INSTALL_DIR=/usr/local

#Check the number of arguments. If none are passed, continue to wizard mode.
NUMARGS=$#
echo -e "Number of arguments: $NUMARGS"\\n


# if user put an illegal switch - print HELP and exit
if [ $? -ne 0 ]; then
  HELP
fi

while [[ $# -gt 0 ]]
do
key="$1"
case $key in
   # default switch - do nothing basically
   --default)
     shift ;;

   # enable libpcap immediate mode
   --use-immediate-mode)
     HAS_PCAP_IMMEDIATE_MODE=1
     shift ;;

   # set direction enabled
   --set-direction-enabled)
     HAS_SET_DIRECTION_ENABLED=1
     shift ;;

   # non-default libpcap include dir
   --libpcap-include-dir)
     LIBPCAP_INLCUDE_DIR=$2
     shift
     shift ;;

   # non-default libpcap lib dir
   --libpcap-lib-dir)
     LIBPCAP_LIB_DIR=$2
     shift
     shift ;;

   # installation directory prefix
   --install-dir)
     INSTALL_DIR=$2
     if [ ! -d "$INSTALL_DIR" ]; then
        echo "Installation directory '$INSTALL_DIR' not found. Exiting..."
        exit 1
     fi
     shift
     shift ;;

   # help switch - display help and exit
   -h|--help)
     HELP ;;

   # empty switch - just go on
   --)
     break ;;

   # illegal switch
   *)
     echo -e \\n"Option $key not allowed.";
     HELP;
     exit 1 ;;
esac
done


PLATFORM_MK="mk/platform.mk"
PCAPPLUSPLUS_MK="mk/PcapPlusPlus.mk"

cp -f mk/platform.mk.freebsd $PLATFORM_MK
cp -f mk/PcapPlusPlus.mk.common $PCAPPLUSPLUS_MK

cat mk/PcapPlusPlus.mk.freebsd >> $PCAPPLUSPLUS_MK

echo -e "\n\nPCAPPLUSPLUS_HOME := "$PWD >> $PLATFORM_MK

sed -i -e '1s|^|PCAPPLUSPLUS_HOME := '$PWD'\'$'\n''\'$'\n''|' $PCAPPLUSPLUS_MK

if (( $HAS_PCAP_IMMEDIATE_MODE > 0 )) ; then
   echo -e "HAS_PCAP_IMMEDIATE_MODE := 1\n\n" >> $PCAPPLUSPLUS_MK
fi

if (( $HAS_SET_DIRECTION_ENABLED > 0 )) ; then
   echo -e "HAS_SET_DIRECTION_ENABLED := 1\n\n" >> $PCAPPLUSPLUS_MK
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
cp mk/install.sh.freebsd.template mk/install.sh
sed -i.bak "s|{{INSTALL_DIR}}|$INSTALL_DIR|g" mk/install.sh && rm mk/install.sh.bak
chmod +x mk/install.sh

cp mk/uninstall.sh.freebsd.template mk/uninstall.sh
sed -i.bak "s|{{INSTALL_DIR}}|$INSTALL_DIR|g" mk/uninstall.sh && rm mk/uninstall.sh.bak
chmod +x mk/uninstall.sh

echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK", mk/install.sh, mk/uninstall.sh
