from datetime import datetime
from datetime import timezone

print("Creating header from downloaded data ...")

# Prepare files
inFile = open("manuf.dat", "r")
outFile = open("../../Common++/src/MacOUILookup.cpp", "w")

Lines = inFile.readlines()
count = 0

# Write header definitions
outFile.write(
    '/***** THIS FILE GENERATED AUTOMATICALLY PLEASE DO NOT MAKE MODIFICATIONS *****/\n\
#include "MacOUILookup.h"\
\n\n\
/// @file\n\
// Created at '
    + datetime.now(timezone.utc).strftime("%m/%d/%Y, %H:%M:%S")
    + " UTC\n\
\n\
/**\n\
 * \\namespace pcpp\n\
 * \\brief The main namespace for the PcapPlusPlus lib\n\
 */\n\
namespace pcpp\n\
{\n\
\n\
// Created from Wireshark Database at https://gitlab.com/wireshark/wireshark/-/raw/master/manuf. Many thanks to its\n\
// contributors!\n\
\n"
)

# Short MAC addresses
outFile.write("std::unordered_map<std::string, std::string> MacVendorListShort = {\n")

alreadyWritten = False
buffer = []
for line in Lines:
    try:
        if buffer != []:
            if alreadyWritten:
                outFile.write(",\n")
            outFile.write(buffer)
            alreadyWritten = True
            count += 1
        line = line.replace('"', '\\"')
        splitted = line.split("\t")
        if len(splitted) >= 3 and len(splitted[0]) == 8:
            buffer = (
                '\t{"'
                + splitted[0].lower().strip()
                + '", "'
                + splitted[2].strip()
                + '"}'
            )
        elif len(splitted) == 2 and len(splitted[0]) == 8:
            buffer = (
                '\t{"'
                + splitted[0].lower().strip()
                + '", "'
                + splitted[1].strip()
                + '"}'
            )
        else:
            buffer = []
    except:
        buffer = []
        continue

if buffer != []:
    outFile.write(",\n")
    outFile.write(buffer)
    count += 1
outFile.write("};\n")
outFile.write("\n")

# Long MAC addresses (with mask)
outFile.write(
    "std::vector<std::pair<int, std::unordered_map<std::string, std::string>>> MacVendorListLong = {\n"
)

outLines = []
maskValues = []
for line in Lines:
    try:
        line = line.replace('"', '\\"')
        splitted = line.split("\t")
        if len(splitted) >= 3 and len(splitted[0]) > 8 and len(splitted[0]) < 21:
            # Process mask
            maskSplit = splitted[0].split("/")
            if len(maskSplit) == 2:
                if maskSplit[1] not in maskValues:
                    maskValues.append(maskSplit[1])
                    outLines.append([])
                indx = maskValues.index(maskSplit[1])
                # Format
                outLines[indx].append(
                    '{"'
                    + maskSplit[0].lower().strip()
                    + '", "'
                    + splitted[2].strip()
                    + '"}'
                )
            else:
                continue
        elif len(splitted) == 2 and len(splitted[0]) > 8 and len(splitted[0]) < 21:
            # Process mask
            maskSplit = splitted[0].split("/")
            if len(maskSplit) == 2:
                if maskSplit[1] not in maskValues:
                    maskValues.append(maskSplit[1])
                    outLines.append([])
                indx = maskValues.index(maskSplit[1])
                # Format
                outLines[indx].append(
                    '{"'
                    + maskSplit[0].lower().strip()
                    + '", "'
                    + splitted[1].strip()
                    + '"}'
                )
            else:
                continue
        else:
            continue
    except:
        continue

# Sorted indices
indx = sorted(range(len(maskValues)), key=lambda k: maskValues[k], reverse=True)
maskValues = [x for _, x in sorted(zip(indx, maskValues))]
outLines = [x for _, x in sorted(zip(indx, outLines))]

ctrIndx = 0
for mask in maskValues:
    alreadyWritten = False
    if ctrIndx:
        outFile.write("\t,\n")
    outFile.write("\t{\n\t\t" + mask + ",\n\t\t{\n")
    for value in outLines[ctrIndx]:
        if alreadyWritten:
            outFile.write(",\n")
        outFile.write("\t\t\t" + value)
        alreadyWritten = True
        count += 1
    ctrIndx += 1
    outFile.write("\n\t\t}\n\t}\n")

outFile.write("};\n")
outFile.write("\n")

outFile.write("} // namespace pcpp\n")

inFile.close()
outFile.close()

print("Total number of vendors is", count)
print("Done!")
