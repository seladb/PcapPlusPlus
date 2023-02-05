#!/bin/sh
set -e

# Rename with .dat extension to prevent typo checks
# wget -O manuf.dat https://gitlab.com/wireshark/wireshark/-/raw/master/manuf

# Create source file from manuf.dat
python3 createOUIData.py

# Convert json information to static C file
mkdir -p include
rm -f include/PCPP_OUIDataset.h
echo "#pragma once \n\nstatic const" >> include/PCPP_OUIDataset.h
xxd -i PCPP_OUIDataset.json >> include/PCPP_OUIDataset.h
