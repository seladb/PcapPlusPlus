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
   echo -e \\n"Help documentation for ${BOLD}${SCRIPT}.${NORM}"\\n
   echo -e "${REV}Basic usage:${NORM} ${BOLD}$SCRIPT [-h] [--use-immediate-mode] ${NORM}"\\n
   echo "The following switches are recognized:"
   echo "${REV}--use-immediate-mode${NORM}  --Use libpcap immediate mode which enables getting packets as fast as possible (supported on libpcap>=1.5)"
   echo ""
   echo -e "${REV}-h|--help${NORM}             --Displays this help message and exits. No further actions are performed"\\n
   echo -e "Examples:"
   echo -e "      ${BOLD}$SCRIPT${NORM}"
   echo -e "      ${BOLD}$SCRIPT --use-immediate-mode${NORM}"
   echo ""
   exit 1
}

HAS_PCAP_IMMEDIATE_MODE=0

#Check the number of arguments. If none are passed, continue to wizard mode.
NUMARGS=$#
echo -e "Number of arguments: $NUMARGS"\\n


# if user put an illegal switch - print HELP and exit
if [ $? -ne 0 ]; then
  HELP
fi

for i in "$@"
do
case $i in
   # default switch - do nothing basically
   --default)
     shift ;;

   # enable libpcap immediate mode
   --use-immediate-mode)
     HAS_PCAP_IMMEDIATE_MODE=1
     shift ;;

   # help switch - display help and exit
   -h|--help)
     HELP
     ;;

   # empty switch - just go on
   --)
     shift ; break ;;

   # illegal switch
   *)
     echo -e \\n"Option -${BOLD}$OPTARG${NORM} not allowed."
     HELP
     ;;
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

echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK"
