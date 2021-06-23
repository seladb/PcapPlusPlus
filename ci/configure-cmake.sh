#!/bin/bash
set -e

# Usage:
#    configure standard (MacOS & Linux) --> ./configure-cmake.sh
#    configure with dpdk (Linux)        --> ./configure-cmake.sh dpdk <DPDK_HOME>
#    configure with pf_ring (Linux)     --> ./configure-cmake.sh pf_ring <PF_RING_HOME>

CMAKE_OPTIONS="-DPCAPPP_BUILD_EXAMPLES=1 -DPCAPPP_BUILD_TESTS=1"

if [[ "$1" == "dpdk" ]]; then
    CMAKE_OPTIONS="$CMAKE_OPTIONS -DPCAPPP_USE_DPDK=1 -DDPDK_HOME:STRING=$2";
fi

if [[ "$1" == "pf_ring" ]]; then
    CMAKE_OPTIONS="$CMAKE_OPTIONS -DPCAPPP_USE_PF_RING=1 -DPF_RING_HOME:STRING=$2";
fi

echo "$CMAKE_OPTIONS"
mkdir build
cd build
cmake .. $CMAKE_OPTIONS
