#!/bin/bash
set -e

make all
cd Tests/Packet++Test && Bin/Packet++Test
cd ../Pcap++Test && Bin/Pcap++Test -n -k 0
cd ../../ && make install
cd Examples/Tutorials/Tutorial-HelloWorld && make -f Makefile.non_windows all;
./Tutorial-HelloWorld;
