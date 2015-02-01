echo ""
echo "****************************************"
echo "PcapPlusPlus Linux configuration script "
echo "****************************************"
echo ""

PLATFORM="mk/platform.mk"

cp -f mk/platform.mk.linux $PLATFORM


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

    echo -e "\n\nPF_RING_HOME := "$PF_RING_HOME >> $PLATFORM
fi

echo "PcapPlusPlus configuration is complete. File created (or modified): $PLATFORM"
