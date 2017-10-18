#!/bin/bash
set -e # Exit with nonzero exit code if anything fails

# remove libs
rm -f /usr/local/lib/libCommon++.a /usr/local/lib/libPacket++.a /usr/local/lib/libPcap++.a

# remove header files
rm -rf /usr/local/include/pcapplusplus

# remove examples
for f in examples/*; do rm /usr/local/bin/$(basename "$f"); done

# remove template makefile
rm -f /usr/local/etc/PcapPlusPlus.mk

# remove PcapPlusPlus.pc
PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-/usr/local/lib/pkgconfig}"
rm -f $PKG_CONFIG_PATH/PcapPlusPlus.pc
