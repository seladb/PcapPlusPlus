#!/bin/bash

echo ""
echo "******************************************"
echo "PcapPlusPlus Android configuration script "
echo "******************************************"
echo ""

# set Script Name variable
SCRIPT=`basename ${BASH_SOURCE[0]}`

# help function
function HELP {
    echo -e \\n"Help documentation for ${SCRIPT}."\\n
    echo ""
    echo -e "Basic usage: $SCRIPT [-h] [--ndk-path] [--target] [--api] [--libpcap-include-dir] [--libpcap-lib-dir]"\\n
    echo "The following switches are recognized:"
    echo "--ndk-path             --The path of Android NDK, for example: '/opt/Android/Sdk/ndk/22.0.7026061'"
    echo "--target               --Target architecture, must be one of these values:"
    echo "                          - aarch64-linux-android"
    echo "                          - armv7a-linux-androideabi"
    echo "                          - i686-linux-android"
    echo "                          - x86_64-linux-android"
    echo "--api                  --Android API level. Must be between 21 and 30"
    echo "--libpcap-include-dir  --libpcap header files directory"
    echo "--libpcap-lib-dir      --libpcap pre compiled lib directory. Please make sure libpcap was compiled with the"
    echo "                         same architecture and API level"
    echo "--help|-h              --Displays this help message and exits. No further actions are performed"\\n
    echo ""
}


if [ $# -eq 0 ]; then
    HELP
    exit 1
fi

# these are all the possible switches
OPTS=`getopt -o h --long ndk-path:,target:,api:,libpcap-lib-dir:,libpcap-include-dir: -- "$@"`

# if user put an illegal switch - print HELP and exit
if [ $? -ne 0 ]; then
    HELP
    exit 1
fi

eval set -- "$OPTS"

# Android-specific variables
NDK_PATH=""
TARGET=""
API=21

# initializing libpcap include/lib dirs to an empty string 
LIBPCAP_INLCUDE_DIR=""
LIBPCAP_LIB_DIR=""

# go over all switches
while true ; do
    case "$1" in
    # NDK path
    --ndk-path)
        NDK_PATH=$2
        if [ ! -d "$NDK_PATH" ]; then
            echo "NDK directory '$NDK_PATH' not found. Exiting..."
            exit 1
        fi
        shift 2 ;;

    # Target
    --target)
        TARGET=$2
        case "$TARGET" in
        aarch64-linux-android|armv7a-linux-androideabi|i686-linux-android|x86_64-linux-android)
            ;;
        *)
            echo -e \\n"Target must be one of:\n- aarch64-linux-android\n- armv7a-linux-androideabi\n- i686-linux-android\n- x86_64-linux-android\nExisting...\n"
            exit 1
        esac
        shift 2 ;;

    # API version
    --api)
        API=$2
        if [[ "$API" -ge 21 && "$API" -le 30 ]]; then
            API=$2
        else
            echo -e \\n"API version must be between 21 and 30. Existing...\n"
            exit 1
        fi
        shift 2 ;;

    # libpcap include dir
    --libpcap-include-dir)
        LIBPCAP_INLCUDE_DIR=$2
        shift 2 ;;

    # libpcap binaries dir
    --libpcap-lib-dir)
        LIBPCAP_LIB_DIR=$2
        shift 2 ;;

    # help switch - display help and exit
    -h|--help)
        HELP
        exit 0
        ;;

    # empty switch - just go on
    --)
        shift ; break ;;

    # illegal switch
    *)
        echo -e \\n"Option -$OPTARG not allowed."
        HELP
        exit 1
    esac
done

if [ -z "$NDK_PATH" ]; then
    echo "Please specify the NDK path using with '--ndk-path'. Exiting..."
    exit 1
fi

if [ -z "$TARGET" ]; then
    echo "Please specify the target using wity '--target'. Exiting..."
    exit 1
fi

if [ -z "$LIBPCAP_INLCUDE_DIR" ]; then
    echo "Please specify the location of libpcap header files with '--libpcap-include-dir'. Exiting..."
    exit 1
fi

if [ -z "$LIBPCAP_LIB_DIR" ]; then
    echo "Please specify the location of libpcap binary that matches the reqruied arch with '--libpcap-lib-dir'. Exiting..."
    exit 1
fi

PLATFORM_MK="mk/platform.mk"
PCAPPLUSPLUS_MK="mk/PcapPlusPlus.mk"

# copy the basic Android platform.mk
cp -f mk/platform.mk.android $PLATFORM_MK

# copy the common (all platforms) PcapPlusPlus.mk
cp -f mk/PcapPlusPlus.mk.common $PCAPPLUSPLUS_MK

# add the Android definitions to PcapPlusPlus.mk
cat mk/PcapPlusPlus.mk.android >> $PCAPPLUSPLUS_MK

# set current directory as PCAPPLUSPLUS_HOME in platform.mk
echo -e "\nPCAPPLUSPLUS_HOME := "$PWD >> $PLATFORM_MK

# set target variable in PcapPlusPlus.mk
sed -i "1s|^|ANDROID_API_VERSION := $API\n\n|" $PCAPPLUSPLUS_MK

# set target variable in PcapPlusPlus.mk
sed -i "1s|^|ANDROID_TARGET := $TARGET$API\n\n|" $PCAPPLUSPLUS_MK

# set NDK path variable in PcapPlusPlus.mk
sed -i "1s|^|ANDROID_NDK_PATH := $NDK_PATH\n\n|" $PCAPPLUSPLUS_MK

# set current direcrtory as PCAPPLUSPLUS_HOME in PcapPlusPlus.mk
sed -i "1s|^|PCAPPLUSPLUS_HOME := $PWD\n\n|" $PCAPPLUSPLUS_MK

# set target variable in platform.mk
sed -i "1s|^|ANDROID_TARGET := $TARGET$API\n\n|" $PLATFORM_MK

# set NDK path variable in platform.mk
sed -i "1s|^|ANDROID_NDK_PATH := $NDK_PATH\n\n|" $PLATFORM_MK

# set libpcap include dir
echo -e "LIBPCAP_INLCUDE_DIR := $LIBPCAP_INLCUDE_DIR" >> $PCAPPLUSPLUS_MK
echo -e "PCAPPP_INCLUDES += -I\$(LIBPCAP_INLCUDE_DIR)\n" >> $PCAPPLUSPLUS_MK

# set libpcap lib dir
echo -e "LIBPCAP_LIB_DIR := $LIBPCAP_LIB_DIR" >> $PCAPPLUSPLUS_MK
echo -e "PCAPPP_LIBS_DIR += -L\$(LIBPCAP_LIB_DIR)\n" >> $PCAPPLUSPLUS_MK

# finished setup script
echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK"