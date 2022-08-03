from datetime import datetime
from datetime import timezone

print("Creating header from downloaded data ...")

# Prepare files
inFile = open("manuf.dat", "r")
outFile = open("PCPP_OUIDatabase.bin", "w")

Lines = inFile.readlines()
count = 0

# Short MAC addresses
outFile.write("PCPP_SHORT_MACS\n")

alreadyWritten = False
buffer = []
for line in Lines:
    try:
        if buffer != []:
            if alreadyWritten:
                outFile.write("\n")
            outFile.write(buffer)
            alreadyWritten = True
            count += 1
        line = line.replace('"', '')
        splitted = line.split("\t")
        if len(splitted) >= 3 and len(splitted[0]) == 8:
            buffer = ( 
                splitted[0].lower().strip()
                + ','
                + splitted[2].strip()
            )
        elif len(splitted) == 2 and len(splitted[0]) == 8:
            buffer = (
                splitted[0].lower().strip()
                + ','
                + splitted[1].strip()
            )
        else:
            buffer = []
    except:
        buffer = []
        continue

if buffer != []:
    outFile.write("\n")
    outFile.write(buffer)
    count += 1
outFile.write("\n")

# Long MAC addresses (with mask)
outFile.write("PCPP_LONG_MACS\n")

outLines = []
maskValues = []
for line in Lines:
    try:
        line = line.replace('"', '')
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
                    maskSplit[0].lower().strip()
                    + ','
                    + splitted[2].strip()
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
                    maskSplit[0].lower().strip()
                    + ','
                    + splitted[1].strip()
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
    outFile.write("MASK " + mask + "\n")
    for value in outLines[ctrIndx]:
        outFile.write(value + "\n")
        count += 1
    ctrIndx += 1

inFile.close()
outFile.close()

print("Total number of vendors is", count)
print("Done!")
