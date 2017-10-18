#!/bin/bash
set -e # Exit with nonzero exit code if anything fails

# copy libs
mkdir -p /usr/local/lib
cp libCommon++.a libPacket++.a libPcap++.a /usr/local/lib

# copy header files
mkdir -p /usr/local/include
mkdir -p /usr/local/include/pcapplusplus
cp header/* /usr/local/include/pcapplusplus

# copy examples
mkdir -p /usr/local/bin
cp examples/* /usr/local/bin

# create template makefile 
cp mk/PcapPlusPlus.mk PcapPlusPlus.mk
sed -i "/PCAPPLUSPLUS_HOME :=/d" PcapPlusPlus.mk
sed -i "/# libs dir/d" PcapPlusPlus.mk
sed -i "/PCAPPP_LIBS_DIR :=/d" PcapPlusPlus.mk
sed -i "s|PCAPPP_INCLUDES :=.*|PCAPPP_INCLUDES := -I/usr/local/include/pcapplusplus|g" PcapPlusPlus.mk

# create PcapPlusPlus.pc
echo 'prefix=/usr/local'>PcapPlusPlus.pc
echo 'exec_prefix=${prefix}'>>PcapPlusPlus.pc
echo 'libdir=${exec_prefix}/lib'>>PcapPlusPlus.pc
echo 'includedir=${prefix}/include'>>PcapPlusPlus.pc
echo>>PcapPlusPlus.pc
echo 'Name: PcapPlusPlus'>>PcapPlusPlus.pc
echo 'Description: a multiplatform C++ network sniffing and packet parsing and crafting framework. It is meant to be lightweight, efficient and easy to use'>>PcapPlusPlus.pc
printf 'Version: '>>PcapPlusPlus.pc
grep '#define PCAPPLUSPLUS_VERSION ' header/PcapPlusPlusVersion.h | cut -d " " -f3 | tr -d "\"" | tr -d '\n'>>PcapPlusPlus.pc
printf '\n'>>PcapPlusPlus.pc
echo 'URL: https://seladb.github.io/PcapPlusPlus-Doc'>>PcapPlusPlus.pc
printf 'Libs: '>>PcapPlusPlus.pc
grep PCAPPP_LIBS ../Dist/PcapPlusPlus.mk | cut -d " " -f3- | tr -d '\r' | tr '\n' ' '>>PcapPlusPlus.pc
printf '\nCFlags: '>>PcapPlusPlus.pc
grep PCAPPP_INCLUDES PcapPlusPlus.mk | cut -d " " -f3- | tr -d '\r' | tr '\n' ' '>>PcapPlusPlus.pc
printf '\n'>>PcapPlusPlus.pc

# copy template makefile
mv PcapPlusPlus.mk /usr/local/etc

# copy PcapPlusPlus.pc
PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-/usr/local/lib/pkgconfig}"
mkdir -p $PKG_CONFIG_PATH
mv PcapPlusPlus.pc $PKG_CONFIG_PATH
