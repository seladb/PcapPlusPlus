#!/bin/bash
set -e # Exit with nonzero exit code if anything fails

TRAVIS_OS_NAME=linux

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then OS_VER=Ubuntu-$(lsb_release -r | awk '{print $2}')-$(uname -m)-gcc-$(gcc -dumpversion); fi
if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then XCODE_VER=$($(xcode-select -print-path)/usr/bin/xcodebuild -version | head -n1 | awk '{print $2}') ; fi
if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then OS_VER=Mac-OSX-$(sw_vers -productVersion)-Xcode-$XCODE_VER; fi

DIST_DIR_NAME=PcapPlusPlus-$(cat Deploy/latest_release.version)-$OS_VER-pf_ring-6.4.1

mv Dist $DIST_DIR_NAME

NEW_FIRST_LINE="PCAPPLUSPLUS_HOME := /your/PcapPlusPlus/folder"
NEW_SECOND_LINE="PF_RING_HOME := /your/pf_ring-6.4.1/folder"

if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then SED_PARAMS="''"; fi

sed -i $SED_PARAMS "1s|.*|$NEW_FIRST_LINE|" $DIST_DIR_NAME/mk/PcapPlusPlus.mk
sed -i $SED_PARAMS "2s|.*|$NEW_SECOND_LINE|" $DIST_DIR_NAME/mk/PcapPlusPlus.mk

sed -i $SED_PARAMS "s|"$(PCAPPLUSPLUS_HOME)/Dist"|"$(PCAPPLUSPLUS_HOME)"|" $DIST_DIR_NAME/mk/PcapPlusPlus.mk

cp Deploy/README.release.pf_ring $DIST_DIR_NAME/README.release
cp -R Examples/ArpSpoofing-SimpleMakefile-Linux $DIST_DIR_NAME/example-app
sed -i $SED_PARAMS "s|"../Dist/"|""|" $DIST_DIR_NAME/example-app/Makefile

tar -zcvf $DIST_DIR_NAME.tar.gz $DIST_DIR_NAME/
curl --upload-file ./$DIST_DIR_NAME.tar.gz https://transfer.sh/$DIST_DIR_NAME.tar.gz
