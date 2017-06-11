DPDK_VER=$1
DPDK_DIR=$2

sudo apt-get install linux-headers-4.4.0-51-generic
wget http://fast.dpdk.org/rel/dpdk-$DPDK_VER.tar.gz
tar xvzf dpdk-$DPDK_VER.tar.gz
cd $DPDK_DIR
make config CC=gcc T=x86_64-native-linuxapp-gcc
make CC=gcc
