from datetime import datetime
from datetime import timezone

print("Creating header from downloaded data ...")

# Prepare files
inFile = open('manuf', 'r')
outFile = open("include/MacLookup.h", "w")

Lines = inFile.readlines()
count = 0

# Write header definitions
outFile.write( \
"/***** THIS HEADER GENERATED AUTOMATICALLY PLEASE DO NOT MAKE MODIFICATIONS *****/\n \
#ifndef PCPP_MACLOOKUP_HEADER\n \
#define PCPP_MACLOOKUP_HEADER\n \
\n \
#include <string>\n \
#include <unordered_map>\n \
\n \
/// @file\n \
// Created at " + datetime.now(timezone.utc).strftime("%m/%d/%Y, %H:%M:%S") + " UTC\n \
\n \
/**\n \
 * \\namespace pcpp\n \
 * \\brief The main namespace for the PcapPlusPlus lib\n \
 */\n \
namespace pcpp\n \
{\n \
\n \
// Created from Wireshark Database at https://gitlab.com/wireshark/wireshark/-/raw/master/manuf. Many thanks to its contributors!\n \
\n")

# Short MAC addresses
outFile.write("/// MAC addresses with only first three octets\n")
outFile.write("std::unordered_map<std::string, std::string> MacVendorListShort = {\n")

alreadyWritten = False
buffer = []
for line in Lines:
    if buffer != []:
        if alreadyWritten:
            outFile.write(",\n")
        outFile.write(buffer)
        alreadyWritten = True
        count += 1
    line = line.replace('\"', '\\\"')
    splitted = line.split('\t')
    if len(splitted) >= 3 and len(splitted[0]) == 8:
        buffer = "\t{\"" + splitted[0].strip() + "\",\"" + splitted[2].strip() + "\"}"
    elif len(splitted) == 2 and len(splitted[0]) == 8:
        buffer = "\t{\"" + splitted[0].strip() + "\",\"" + splitted[1].strip() + "\"}"
    else:
        buffer = []

if buffer != []:
    outFile.write(",\n")
    outFile.write(buffer)
    count += 1
outFile.write("};\n")
outFile.write("\n")

# Long MAC addresses
outFile.write("/// Full MAC addresses\n")
outFile.write("std::unordered_map<std::string, std::string> MacVendorListLong = {\n")

alreadyWritten = False
buffer = []
for line in Lines:
    if buffer != []:
        if alreadyWritten:
            outFile.write(",\n")
        outFile.write(buffer)
        alreadyWritten = True
        count += 1
    line = line.replace('\"', '\\\"')
    splitted = line.split('\t')

    if len(splitted) >= 3 and len(splitted[0]) > 8:
        # Process mask

        # Format
        buffer = "\t{\"" + splitted[0].strip() + "\",\"" + splitted[2].strip() + "\"}"
    elif len(splitted) == 2 and len(splitted[0]) > 8:
        # Process mask

        buffer = "\t{\"" + splitted[0].strip() + "\",\"" + splitted[1].strip() + "\"}"
    else:
        buffer = []

if buffer != []:
    outFile.write(",\n")
    outFile.write(buffer)
    count += 1
outFile.write("};\n")
outFile.write("\n")

outFile.write("} // namespace pcpp\n")
outFile.write("#endif // /* PCPP_MACLOOKUP_HEADER */\n")

inFile.close()
outFile.close()

print("Total number of vendors is", count)
print("Done!")
