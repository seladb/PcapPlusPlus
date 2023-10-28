#!/bin/sh
set -e

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
ROOTPATH=$(realpath "${SCRIPTPATH}"/..)
if ! command -v cmake-format; then
    echo "cmake-format is not found!"
    exit 1
fi

find "${ROOTPATH}" -type f \( -name '*.cmake' -o -name 'CMakeLists.txt' \) -not -path "*/3rdParty/*" -exec echo 'Formatting:' {} ';' -exec cmake-format -i {} ';'
