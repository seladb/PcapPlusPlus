#!/bin/sh
set -e

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
ROOTPATH=$(realpath "${SCRIPTPATH}"/..)
if ! command -v clang-format; then
    echo "clang-format is not found!"
    exit 1
fi

# Check the version of clang-format
python3 ./ci/check-clang-format-version.py

# Determine the mode (all files or changed files)
MODE=${1:-all}

if [ "$MODE" = "changed" ]; then
    # Get the list of changed files from origin/dev
    files=$(git diff --name-only upstream/dev -- '*.cpp' '*.h' | grep -v '3rdParty/' || true)
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
    echo "Checking: $file"
    clang-format --style=file -i "$file"
done
