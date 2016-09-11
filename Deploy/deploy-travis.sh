#!/bin/bash
set -e # Exit with nonzero exit code if anything fails

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then OS_VER=Ubuntu-$(lsb_release -r | awk '{print $2}')-$(uname -m)-gcc-$(gcc -dumpversion); fi
if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then XCODE_VER=$($(xcode-select -print-path)/usr/bin/xcodebuild -version | head -n1 | awk '{print $2}') ; fi
if [[ "$TRAVIS_OS_NAME" == "osx" ]]; then OS_VER=Mac-OSX-$(sw_vers -productVersion)-Xcode-$XCODE_VER; fi

DIST_DIR_NAME=PcapPlusPlus-$(cat latest_release.version)-$OS_VER

mv Dist $DIST_DIR_NAME

NEW_FIRST_LINE="PCAPPLUSPLUS_HOME := /your/PcapPlusPlus/folder"
sed -i "1s|.*|$NEW_FIRST_LINE|" $DIST_DIR_NAME/mk/PcapPlusPlus.mk

sed -i "s|"$(PCAPPLUSPLUS_HOME)/Dist"|"$(PCAPPLUSPLUS_HOME)"|" $DIST_DIR_NAME/mk/PcapPlusPlus.mk

cp Deploy/README.release $DIST_DIR_NAME/

rm $DIST_DIR_NAME/mk/platform.mk

tar -zcvf $DIST_DIR_NAME.tar.gz $DIST_DIR_NAME/
curl --upload-file ./$DIST_DIR_NAME.tar.gz https://transfer.sh/$DIST_DIR_NAME.tar.gz
