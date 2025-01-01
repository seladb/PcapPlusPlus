#!/bin/sh
set -e

IGNORE_LIST=".*dirent.* .*DpdkDevice* .*KniDevice* .*MBufRawPacket* .*PfRingDevice* .*RemoteDevice* .*XdpDevice* .*WinPcap* .*Examples* .*Tests* .*build* .*3rdParty* .*Packet\+\+* .*Pcap\+\+*"

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
ROOTPATH=$(realpath "${SCRIPTPATH}"/..)
if ! command -v clang-tidy; then
    echo "clang-tidy is not found!"
    exit 1
fi

# Determine the mode (all files or changed files)
MODE=${1:-all}
BUILD_DIR=${2:-build}

if [ "$MODE" = "changed" ]; then
    # Get the list of changed files from origin/dev
    git fetch origin dev
    files=$(git diff --name-only origin/dev -- '*.cpp' '*.h' | grep -v '3rdParty/' || true)
else
    # Find all relevant files
    files=$(find "${ROOTPATH}" -type f \( -name '*.cpp' -o -name '*.h' \) -not -path "*/3rdParty/*")
fi

# Check if there are any files to process
if [ -z "$files" ]; then
    echo "No files to process."
    exit 0
fi

# Process each file
echo "$files" | while IFS= read -r file; do
    for ignore in $IGNORE_LIST; do
        if echo "$file" | grep -qE "$ignore"; then
            echo "Ignoring: $file"
            continue 2
        fi
    done
    echo "Checking: $file"
    clang-tidy "$file" -p $BUILD_DIR --fix
done
