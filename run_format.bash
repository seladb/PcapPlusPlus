#!/bin/bash

list=('Common++' 'Packet++' 'Pcap++' 'Examples')
for folder in "${list[@]}"; do
    find "$folder" \( -name "*.cpp" -o -name "*.h" \) -exec clang-format -i {} +
done
