echo ""
echo "*******************************************"
echo "PcapPlusPlus Mac OS X configuration script "
echo "*******************************************"
echo ""

PLATFORM_MK="mk/platform.mk"
PCAPPLUSPLUS_MK="mk/PcapPlusPlus.mk"

cp -f mk/platform.mk.macosx $PLATFORM_MK
cp -f mk/PcapPlusPlus.mk.common $PCAPPLUSPLUS_MK
cat mk/PcapPlusPlus.mk.macosx >> $PCAPPLUSPLUS_MK

echo "\n\nPCAPPLUSPLUS_HOME := "$PWD >> $PLATFORM_MK

sed -i "" -e '1s|^|PCAPPLUSPLUS_HOME := '$PWD'\'$'\n''\'$'\n''|' $PCAPPLUSPLUS_MK

echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK"
