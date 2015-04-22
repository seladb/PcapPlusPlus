echo ""
echo "****************************************"
echo "PcapPlusPlus Linux configuration script "
echo "****************************************"
echo ""

PLATFORM_MK="mk/platform.mk"
PCAPPLUSPLUS_MK="mk/PcapPlusPlus.mk"

cp -f mk/platform.mk.linux $PLATFORM_MK
cp -f mk/PcapPlusPlus.mk.common $PCAPPLUSPLUS_MK
cat mk/PcapPlusPlus.mk.linux >> $PCAPPLUSPLUS_MK

echo -e "\n\nPCAPPLUSPLUS_HOME := "$PWD >> $PLATFORM_MK

sed -i "1s|^|PCAPPLUSPLUS_HOME := $PWD\n\n|" $PCAPPLUSPLUS_MK

COMPILE_WITH_PF_RING=0

while true; do
    read -p "Compile PcapPlusPlus with PF_RING? " yn
    case $yn in
        [Yy]* ) COMPILE_WITH_PF_RING=1; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no";;
    esac
done

if (( $COMPILE_WITH_PF_RING > 0 )) ; then
    while true; do
        read -e -p "Enter PF_RING source path: " PF_RING_HOME
        if [ -d "$PF_RING_HOME" ]; then
            break;
        else
            echo "Directory doesn't exists"
        fi
    done

    cat mk/PcapPlusPlus.mk.pf_ring >> $PCAPPLUSPLUS_MK

    echo -e "\n\nPF_RING_HOME := "$PF_RING_HOME >> $PLATFORM_MK
    
    sed -i "2s|^|PF_RING_HOME := $PF_RING_HOME\n\n|" $PCAPPLUSPLUS_MK
fi

echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK"
