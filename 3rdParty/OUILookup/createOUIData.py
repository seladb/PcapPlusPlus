import json

print("Creating header from downloaded data ...")

# Prepare files
inFile = open("manuf.dat", "r")
outFile = open("PCPP_OUIDataset.json", "w")
Lines = inFile.readlines()

countSuccess = 0
countFail = 0
readMAC = ''
readVendor = ''
oldMacAddress = 0
mainJson = {}
bufferJson = {}

# Every line is a new MAC address
for line in Lines:
    try:
        # Prepare line
        line = line.replace('"', "")
        splitLine = line.split("\t")

        if len(splitLine) >= 3 and len(splitLine[0]) == 8:
            readMAC = splitLine[0].lower().strip()
            readVendor = splitLine[2].strip()
        elif len(splitLine) == 2 and len(splitLine[0]) == 8:
            readMAC = splitLine[0].lower().strip()
            readVendor = splitLine[1].strip()
        elif len(splitLine) == 2 and len(splitLine[0]) > 8 and len(splitLine[0]) < 21:
            maskSplit = splitLine[0].split("/")
            if len(maskSplit) == 2:
                readMask = int(maskSplit[1])
            else:
                raise Exception("Unknown number of elements for masking long MAC address", line)
        elif len(splitLine) == 3 and len(splitLine[0]) > 8 and len(splitLine[0]) < 21:
            maskSplit = splitLine[0].split("/")
            if len(maskSplit) == 2:
                readMask = int(maskSplit[1])
            else:
                raise Exception("Unknown number of elements for masking long MAC address", line)
        elif (line[0] != '#') or (line[0] != '\n'):
            raise Exception("") 
        else:
            raise Exception("Unkown number of elements for line", line)
        
        if len(readMAC) == 8: # If equal to 8 should be a non-masked (short) MAC address
            currentMacAddress = int(readMAC.replace(":",''), 16)
            mainJson.update({currentMacAddress:{"vendor":readVendor}})
            oldMacAddress == currentMacAddress
        else: # Otherwise this should be a masked (long) MAC address
            continue # <--------------------------
        countSuccess = countSuccess + 1
    except Exception as e:
        if hasattr(e, 'message'):
            print(e)
            countFail = countFail + 1
        readMAC = ''
        readVendor = ''
        readMask = 0
        continue

print("Total number of vendors is", countSuccess, "failed", countFail)
print("Writing file")
outFile.write(json.dumps(mainJson, indent=4))

inFile.close()
outFile.close()

print("Done!")
