#!/bin/sh
set -e

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
ROOTPATH=$(realpath "${SCRIPTPATH}"/..)
if ! command -v cppcheck; then
    echo "cppcheck is not found!"
    exit 1
fi

# Create a temporary file to track the overall status
status_file=$(mktemp)
echo 0 > "$status_file"

# Determine the mode (all files or changed files)
MODE=${1:-all}

if [ "$MODE" = "changed" ]; then
    # Get the list of changed files from origin/dev
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
    echo "Checking: $file"
    if ! cppcheck -q --error-exitcode=1 --enable=all --std=c++11 --language=c++ --suppressions-list=cppcheckSuppressions.txt --inline-suppr --force "$file"; then
        echo 1 > "$status_file"
    fi
done

# Read the overall status from the temporary file
overall_status=$(cat "$status_file")
rm "$status_file"

exit $overall_status
