#!/bin/bash
set -e

TARGETS_DIR=build/

# Build libpcap
cd $SRC/libpcap/
./autogen.sh
./configure --enable-shared=no
make -j$(nproc)

# Build PcapPlusPlus linking statically against the built libpcap
cd $SRC/PcapPlusPlus
LIBPCAP_PATH=$SRC/libpcap/
cmake -DPCAPPP_BUILD_FUZZERS=ON -DPCAPPP_BUILD_TESTS=OFF -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAP_INCLUDE_DIR="${LIBPCAP_PATH}/" -DPCAP_LIBRARY="${LIBPCAP_PATH}/libpcap.a" -S . -B $TARGETS_DIR
cmake --build $TARGETS_DIR -j

# Copy target and options
FUZZERS="FuzzTarget \
    FuzzTargetNg \
    FuzzTargetSnoop \
    FuzzWriter \
    FuzzWriterNg"

for fuzzer in $FUZZERS; do
    cp $TARGETS_DIR/Tests/Fuzzers/${fuzzer} $OUT
    cp $(ldd $OUT/${fuzzer} | cut -d" " -f3) $OUT
    cp Tests/Fuzzers/default.options $OUT/${fuzzer}.options
done

# Copy corpora
find $SRC/ -iname "*.pcap"   | xargs zip $OUT/FuzzTarget_seed_corpus.zip
find $SRC/ -iname "*.pcapng" | xargs zip $OUT/FuzzTargetNg_seed_corpus.zip
find $SRC/ -iname "*.snoop"  | xargs zip $OUT/FuzzTargetSnoop_seed_corpus.zip
find $SRC/ -iname "*.pcap"   | xargs zip $OUT/FuzzWriter_seed_corpus.zip
find $SRC/ -iname "*.pcapng" | xargs zip $OUT/FuzzWriterNg_seed_corpus.zip
