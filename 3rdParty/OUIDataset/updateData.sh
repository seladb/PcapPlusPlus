#!/bin/sh
set -e

# Download manuf.dat and create source file in json format
python3 create_oui_data.py

# Convert json information to static C file
mkdir -p include
rm -f include/PCPP_OUIDataset.h
echo "#pragma once\n\nstatic const" >> include/PCPP_OUIDataset.h
xxd -i PCPP_OUIDataset.json >> include/PCPP_OUIDataset.h
