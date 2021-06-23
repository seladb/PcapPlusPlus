#!/bin/bash
set -e

# Usage:
#    configure for MacOS            --> ./configure-standard.sh osx
#    configure for Linux            --> ./configure-standard.sh linux
#    configure with dpdk (Linux)    --> ./configure-standard.sh linux dpdk <DPDK_HOME>
#    configure with pf_ring (Linux) --> ./configure-standard.sh linux pf_ring <PF_RING_HOME>

if [ "$#" -lt 1 ]; then
   echo "No parameters provided";
   exit 1;
fi

PLATFORM_OS=$1
COMPILE_WITH_DPDK=0
COMPILE_WITH_PF_RING=0
DPDK_HOME=""
PF_RING_HOME=""

if [[ "$2" == "dpdk" ]]; then
    COMPILE_WITH_DPDK=1;
    DPDK_HOME=$3;
fi

if [[ "$2" == "pf_ring" ]]; then
    COMPILE_WITH_PF_RING=1;
    PF_RING_HOME=$3;
fi

if [[ "$PLATFORM_OS" == "osx" ]]; then ./configure-mac_os_x.sh; fi
if [[ "$PLATFORM_OS" == "linux" ]]; then ./configure-linux.sh --default; fi;
if [[ $COMPILE_WITH_DPDK > 0 ]]; then ./configure-linux.sh --dpdk --dpdk-home $DPDK_HOME; fi;
if [[ $COMPILE_WITH_PF_RING > 0 ]]; then ./configure-linux.sh --pf-ring --pf-ring-home $PF_RING_HOME; fi;
