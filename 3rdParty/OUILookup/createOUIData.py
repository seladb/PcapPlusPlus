import json

print("Creating header from downloaded data ...")

# Prepare files
inFile = open("manuf.dat", "r")
outFile = open("PCPP_OUIDataset.json", "w", encoding='utf8')
Lines = inFile.readlines()

countSuccess = 0
countFail = 0
readMAC = ""
readVendor = ""
mainJson = {}
vMask = []
vMaskedVendors = {}

# Every line is a new MAC address
for line in Lines:
    try:
        readMask = 0
        readMACShort = ""
        readMACLong = ""
        readVendor = ""

        # Prepare line
        line = line.replace('"', "")
        splitLine = line.split("\t")

        # MAC + Short name
        if len(splitLine) == 2 and len(splitLine[0]) == 8:
            readMACShort = splitLine[0].lower().strip()
            readVendor = splitLine[1].strip()
        # MAC + Short name + Long name
        elif len(splitLine) >= 3 and len(splitLine[0]) == 8:
            readMACShort = splitLine[0].lower().strip()
            readVendor = splitLine[2].strip()
        # MAC/Mask + Short name
        elif len(splitLine) == 2 and len(splitLine[0]) > 8 and len(splitLine[0]) < 21:
            maskSplit = splitLine[0].split("/")
            if len(maskSplit) == 2:
                readMACLong = maskSplit[0].lower().strip()
                readMACShort = maskSplit[0][0:8].lower().strip()
                readVendor = splitLine[1].strip()
                readMask = int(maskSplit[1])
            else:
                raise Exception(
                    "Unknown number of elements for masking long MAC address", line
                )
        # MAC/Mask + Short name + Long name
        elif len(splitLine) == 3 and len(splitLine[0]) > 8 and len(splitLine[0]) < 21:
            maskSplit = splitLine[0].split("/")
            if len(maskSplit) == 2:
                readMACLong = maskSplit[0].lower().strip()
                readMACShort = maskSplit[0][0:8].lower().strip()
                readVendor = splitLine[2].strip()
                readMask = int(maskSplit[1])
            else:
                raise Exception(
                    "Unknown number of elements for masking long MAC address", line
                )
        # Comment lines
        elif (line[0] != "#") or (line[0] != "\n"):
            raise Exception("")
        else:
            raise Exception("Unknown number of elements for line", line)

        # If equal to 0 should be a non-masked (short) MAC address
        if readMask == 0:
            if len(vMask):
                mainJson[currentMacAddressShort]["maskedFilters"] = []
                for i in range(0, len(vMask)):
                    mainJson[currentMacAddressShort]["maskedFilters"].append(
                        {"mask": vMask[i], "vendors": vMaskedVendors[i]}
                    )
            currentMacAddressShort = int(readMACShort.replace(":", ""), 16)
            mainJson[currentMacAddressShort] = {"vendor": readVendor}
            vMask = []
            vMaskedVendors = []
        # Otherwise this should be a masked (long) MAC address
        else:
            currentMacAddressLong = int(readMACLong.replace(":", ""), 16)
            if readMask in vMask:
                indx = vMask.index(readMask)
            else:
                vMask.append(readMask)
                vMaskedVendors.append({})
                indx = len(vMask) - 1
            vMaskedVendors[indx][currentMacAddressLong] = readVendor
        countSuccess = countSuccess + 1
    except Exception as e:
        if hasattr(e, "message"):
            print(e)
            countFail = countFail + 1

# Append last buffer
if len(vMask):
    mainJson[currentMacAddressShort]["maskedFilters"] = []
    for i in range(0, len(vMask)):
        mainJson[currentMacAddressShort]["maskedFilters"].append(
            {"mask": vMask[i], "vendors": vMaskedVendors[i]}
        )

# Dump to file
print("Total number of vendors is", countSuccess, "failed", countFail)
print("Writing file")
outFile.write(json.dumps(mainJson, indent=4, ensure_ascii=False))
outFile.write('\n')

inFile.close()
outFile.close()

print("Done!")
