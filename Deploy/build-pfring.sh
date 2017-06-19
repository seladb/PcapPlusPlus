git clone https://github.com/ntop/PF_RING.git
cd PF_RING

LATEST_TAG=$(git describe --tags --abbrev=0)
git checkout ${LATEST_TAG}

cd kernel
make

sudo insmod ./pf_ring.ko

cd ../userland
make
