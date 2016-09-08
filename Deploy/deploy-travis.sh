#!/bin/bash
set -e # Exit with nonzero exit code if anything fails

DIST_DIR_NAME=Dist-$TRAVIS_OS_NAME
mv Dist $DIST_DIR_NAME

NEW_FIRST_LINE="PCAPPLUSPLUS_HOME := /your/PcapPlusPlus/folder"
sed -i "1s|.*|$NEW_FIRST_LINE|" $DIST_DIR_NAME/mk/PcapPlusPlus.mk

sed -i "s|"$(PCAPPLUSPLUS_HOME)/Dist"|"$(PCAPPLUSPLUS_HOME)"|" $DIST_DIR_NAME/mk/PcapPlusPlus.mk

cp Deploy/README.release $DIST_DIR_NAME/

rm $DIST_DIR_NAME/mk/platform.mk

tar -zcvf $DIST_DIR_NAME-$TRAVIS_JOB_NUMBER.tar.gz $DIST_DIR_NAME/
curl --upload-file ./$DIST_DIR_NAME.tar.gz https://transfer.sh/$DIST_DIR_NAME.tar.gz
