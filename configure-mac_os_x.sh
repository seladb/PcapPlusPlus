#!/bin/bash

echo ""
echo "*******************************************"
echo "PcapPlusPlus Mac OS X configuration script "
echo "*******************************************"
echo ""

# set Script Name variable
SCRIPT=`basename ${BASH_SOURCE[0]}`

# help function
function HELP {
   echo -e \\n"Help documentation for ${SCRIPT}."\\n
   echo -e "Basic usage: $SCRIPT [-h] [--use-immediate-mode] [--install-dir] [--libpcap-include-dir] [--libpcap-lib-dir]"\\n
   echo "The following switches are recognized:"
   echo "--use-immediate-mode  --Use libpcap immediate mode which enables getting packets as fast as possible (supported on libpcap>=1.5)"
   echo ""
   echo "--install-dir         --Set installation directory. Default is /usr/local"
   echo ""
   echo "--libpcap-include-dir --libpcap header files directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "                        the header files in the default include paths"
   echo "--libpcap-lib-dir     --libpcap pre compiled lib directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "                        the lib file in the default lib paths"
   echo ""
   echo -e "-h|--help             --Displays this help message and exits. No further actions are performed"\\n
   echo -e "Examples:"
   echo -e "      $SCRIPT"
   echo -e "      $SCRIPT --use-immediate-mode"
   echo -e "      $SCRIPT --libpcap-include-dir /home/myuser/my-libpcap/include --libpcap-lib-dir /home/myuser/my-libpcap/lib"
   echo -e "      $SCRIPT --install-dir /home/myuser/my-install-dir"
   echo ""
   exit 1
}

HAS_PCAP_IMMEDIATE_MODE=0

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

EXPECTING_VALUE=0
for i in "$@"
do
case $i in
   # default switch - do nothing basically
   --default)
     ;;

   # enable libpcap immediate mode
   --use-immediate-mode)
     HAS_PCAP_IMMEDIATE_MODE=1 ;;

   # non-default libpcap include dir
   --libpcap-include-dir)
     LIBPCAP_INLCUDE_DIR=$2
     EXPECTING_VALUE=1 ;;

   # non-default libpcap lib dir
   --libpcap-lib-dir)
     LIBPCAP_LIB_DIR=$2
     EXPECTING_VALUE=1 ;;

   # installation directory prefix
   --install-dir)
     INSTALL_DIR=$2
     if [ ! -d "$INSTALL_DIR" ]; then
        echo "Installation directory '$INSTALL_DIR' not found. Exiting..."
        exit 1
     fi
     EXPECTING_VALUE=1 ;;

   # help switch - display help and exit
   -h|--help)
     HELP ;;

   # empty switch - just go on
   --)
     break ;;

   # illegal switch
   *)
     if [ "$EXPECTING_VALUE" -eq "1" ]; then
        EXPECTING_VALUE=0
     else
        echo -e \\n"Option $i not allowed.";
        HELP;
     fi ;;
esac
done


PLATFORM_MK="mk/platform.mk"
PCAPPLUSPLUS_MK="mk/PcapPlusPlus.mk"

cp -f mk/platform.mk.macosx $PLATFORM_MK
cp -f mk/PcapPlusPlus.mk.common $PCAPPLUSPLUS_MK
cat mk/PcapPlusPlus.mk.macosx >> $PCAPPLUSPLUS_MK

echo -e "\n\nPCAPPLUSPLUS_HOME := "$PWD >> $PLATFORM_MK

sed -i -e '1s|^|PCAPPLUSPLUS_HOME := '$PWD'\'$'\n''\'$'\n''|' $PCAPPLUSPLUS_MK

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

echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK", mk/install.sh, mk/uninstall.sh
