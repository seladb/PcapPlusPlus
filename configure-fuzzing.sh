#!/bin/bash

echo ""
echo "*****************************************"
echo "PcapPlusPlus Fuzzing configuration script"
echo "*****************************************"
echo ""

# set Script Name variable
SCRIPT=`basename ${BASH_SOURCE[0]}`

# help function
function HELP {
   echo -e \\n"Help documentation for ${SCRIPT}."\\n
   echo ""
   echo -e "Basic usage: $SCRIPT [-h] [--default] [--sanitizer=address|memory|undefined] [--install-dir] [--libpcap-include-dir] [--libpcap-lib-dir] [--libpcap-static-lib-dir]"\\n
   echo "The following switches are recognized:"
   echo "--default                --Setup PcapPlusPlus for Linux without PF_RING or DPDK. In this case you must not set --pf-ring or --dpdk"
   echo ""
   echo "--sanitizer              --Build fuzzer target with the specified Sanitizer. By default Address Sanitizer (ASan) will be used. Valid options: "
   echo "                           * address: Address Sanitizer. More info: https://clang.llvm.org/docs/AddressSanitizer.html"
   echo "                           * memory: Memory Sanitizer. More info: https://clang.llvm.org/docs/MemorySanitizer.html"
   echo "                           * undefined: Undefined Behavior Sanitizer. More info: https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html"
   echo ""
   echo "--install-dir            --Installation directory. Default is /usr/local"
   echo ""
   echo "--libpcap-include-dir    --libpcap header files directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "                           the header files in the default include paths"
   echo "--libpcap-lib-dir        --libpcap pre compiled lib directory. This parameter is optional and if omitted PcapPlusPlus will look for"
   echo "--libpcap-static-lib-dir --static libpcap + headers directory. Build PcapPlusPlus linking against static libpcap library"
   echo "                           the lib file in the default lib paths"
   echo ""
   echo -e "-h|--help                --Displays this help message and exits. No further actions are performed"\\n
   echo -e "Examples:"
   echo -e "      $SCRIPT --default"
   echo -e "      $SCRIPT --sanitizer address"
   echo -e "      $SCRIPT --libpcap-include-dir /home/myuser/my-libpcap/include --libpcap-lib-dir /home/myuser/my-libpcap/lib"
   echo -e "      $SCRIPT --install-dir /home/myuser/my-install-dir"
   echo -e "      $SCRIPT --libpcap-static-lib-dir /home/myuser/my-static-libpcap"
   echo ""
   exit 1
}

# initializing libpcap include/lib dirs to an empty string
LIBPCAP_INLCUDE_DIR=""
LIBPCAP_LIB_DIR=""

LIBPCAP_STATIC_LIB_DIR=""

SANITIZER=""

# default installation directory
INSTALL_DIR=/usr/local

#Check the number of arguments. If none are passed, continue to wizard mode.
NUMARGS=$#
echo -e "Number of arguments: $NUMARGS"\\n

# start wizard mode
if [ $NUMARGS -eq 0 ]; then
	HELP
# script was run with parameters, go to param mode
else

   # these are all the possible switches
   OPTS=`getopt -o h --long default,help,sanitizer:,install-dir:,libpcap-include-dir:,libpcap-lib-dir:,libpcap-static-lib-dir: -- "$@"`

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

       # non-default sanitizer
       --sanitizer)
         SANITIZER=$2
         shift 2 ;;

       # non-default libpcap include dir
       --libpcap-include-dir)
         LIBPCAP_INLCUDE_DIR=$2
         shift 2 ;;

       # non-default libpcap lib dir
       --libpcap-lib-dir)
	     LIBPCAP_LIB_DIR=$2
         shift 2 ;;

       # static libpcap + includes dir
       --libpcap-static-lib-dir)
         LIBPCAP_STATIC_LIB_DIR=$2
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

   ### End getopts code ###
fi


PLATFORM_MK="mk/platform.mk"
PCAPPLUSPLUS_MK="mk/PcapPlusPlus.mk"

# copy the fuzzing platform.mk
cp -f mk/platform.mk.fuzzing $PLATFORM_MK

# copy the common (all platforms) PcapPlusPlus.mk
cp -f mk/PcapPlusPlus.mk.common $PCAPPLUSPLUS_MK

# if build against static libpcap
if [ -n "$LIBPCAP_STATIC_LIB_DIR" ]; then
   echo -e "STATIC_LIBPCAP_INCLUDE := $LIBPCAP_STATIC_LIB_DIR" >> $PCAPPLUSPLUS_MK
   echo -e "STATIC_LIBPCAP_LIB := $LIBPCAP_STATIC_LIB_DIR/libpcap.a" >> $PCAPPLUSPLUS_MK
   echo -e "PCAPPP_INCLUDES += -I\$(STATIC_LIBPCAP_INCLUDE)" >> $PCAPPLUSPLUS_MK
   echo -e "PCAPPP_LIBS += \$(STATIC_LIBPCAP_LIB)" >> $PCAPPLUSPLUS_MK
   echo -e "BUILD_WITH_STATIC_LIBPCAP := 1" >> $PCAPPLUSPLUS_MK
else
   echo -e "PCAPPP_LIBS += -lpcap" >> $PCAPPLUSPLUS_MK
fi

# sanitizer options
case "$SANITIZER" in
	address|memory|undefined)
		;;
	*)
		echo -e \\n"No Sanitizer was provided or --sanitizer option value was invalid. Using Address Sanitizer (address) as default.\n"
		SANITIZER=address
		;;
esac
echo -e "ifeq (\$(origin CXXFLAGS), file)\nCXXFLAGS += -fsanitize=$SANITIZER\nendif\n" >> $PLATFORM_MK
echo -e "ifeq (\$(origin LIB_FUZZING_ENGINE), file)\nLIB_FUZZING_ENGINE += -fsanitize=$SANITIZER\nendif\n" >> $PLATFORM_MK

# set current directory as PCAPPLUSPLUS_HOME in platform.mk
echo -e "\n\nPCAPPLUSPLUS_HOME := "$PWD >> $PLATFORM_MK

# set current direcrtory as PCAPPLUSPLUS_HOME in PcapPlusPlus.mk (write it in the first line of the file)
sed -i "1s|^|PCAPPLUSPLUS_HOME := $PWD\n\n|" $PCAPPLUSPLUS_MK

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
chmod +x mk/uninstall.sh


# finished setup script
echo -e 'WARNING: To build PcapPlusPlus for fuzzing use "make fuzzers". "make all" or "make" will attempt to build the tests and examples, which will fail with this build configuration.\n'
echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK, mk/install.sh, mk/uninstall.sh"
