#!/bin/sh
set -e

# Rename with .dat extension to prevent typo checks
wget -O manuf.dat https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
# Create source file from manuf.dat
python3 createOUIData.py
