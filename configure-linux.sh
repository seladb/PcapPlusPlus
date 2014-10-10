echo ""
echo "****************************************"
echo "PcapPlusPlus Linux configuration script "
echo "****************************************"
echo ""

PLATFORM="mk/platform.mk"

cp -f mk/platform.mk.linux $PLATFORM

echo "PcapPlusPlus configuration is complete. File created (or modified): $PLATFORM"
