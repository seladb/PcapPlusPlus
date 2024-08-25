#!/bin/sh
set -e

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
ROOTPATH=$(realpath "${SCRIPTPATH}"/..)
if ! command -v cmake-format; then
    echo "cmake-format is not found!"
    exit 1
fi

# Determine the mode (all files or changed files)
MODE=${1:-all}

if [ "$MODE" = "changed" ]; then
    # Get the list of changed files from origin/dev
    files=$(git diff --name-only origin/dev -- '*.cmake' 'CMakeLists.txt' | grep -v '3rdParty/' || true)
else
    # Find all relevant files
    files=$(find "${ROOTPATH}" -type f \( -name '*.cmake' -o -name 'CMakeLists.txt' \) -not -path "*/3rdParty/*")
fi

# Check if there are any files to process
if [ -z "$files" ]; then
    echo "No files to process."
    exit 0
fi

# Process each file
echo "$files" | while IFS= read -r file; do
    echo "Checking: $file"
    cmake-format -i "$file"
done
