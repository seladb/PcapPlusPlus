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

COMPILE_WITH_DPDK=0

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
            echo "Directory doesn't exist"
        fi
    done

    cat mk/PcapPlusPlus.mk.pf_ring >> $PCAPPLUSPLUS_MK

    echo -e "\n\nPF_RING_HOME := "$PF_RING_HOME >> $PLATFORM_MK
    
    sed -i "2s|^|PF_RING_HOME := $PF_RING_HOME\n\n|" $PCAPPLUSPLUS_MK
fi

while true; do
    read -p "Compile PcapPlusPlus with DPDK? " yn
    case $yn in
        [Yy]* ) COMPILE_WITH_DPDK=1; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no";;
    esac
done

if (( $COMPILE_WITH_DPDK > 0 )) ; then
    while true; do
        read -e -p "Enter DPDK source path: " DPDK_HOME
        if [ -d "$DPDK_HOME" ]; then
            break;
        else
            echo "Directory doesn't exist"
        fi
    done

    while true; do
        read -e -p "Enter DPDK build path: " -i $DPDK_HOME/ DPDK_TARGET
        DPDK_TARGET="$(basename $DPDK_TARGET)"
        if [ -d "$DPDK_HOME/$DPDK_TARGET" ]; then
            break;
        else
            echo "Directory doesn't exist"
        fi
    done

    cat mk/PcapPlusPlus.mk.dpdk >> $PCAPPLUSPLUS_MK

    echo -e "\n\nUSE_DPDK := 1" >> $PLATFORM_MK

    echo -e "\n\nRTE_SDK := "$DPDK_HOME >> $PLATFORM_MK

    echo -e "\n\nRTE_TARGET := "$DPDK_TARGET >> $PLATFORM_MK

    sed -i "2s|^|USE_DPDK := 1\n\n|" $PCAPPLUSPLUS_MK
    
    sed -i "2s|^|RTE_TARGET := $DPDK_TARGET\n\n|" $PCAPPLUSPLUS_MK

    sed -i "2s|^|RTE_SDK := $DPDK_HOME\n\n|" $PCAPPLUSPLUS_MK

    cp mk/setup-dpdk.sh.template setup-dpdk.sh

    chmod +x setup-dpdk.sh

    sed -i "s|###RTE_SDK###|$DPDK_HOME|g" setup-dpdk.sh

    sed -i "s|###RTE_TARGET###|$DPDK_TARGET|g" setup-dpdk.sh
fi

echo "PcapPlusPlus configuration is complete. Files created (or modified): $PLATFORM_MK, $PCAPPLUSPLUS_MK"
