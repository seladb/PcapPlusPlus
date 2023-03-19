#!/bin/sh
set -e

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
ROOTPATH=${SCRIPTPATH}/..

find "${ROOTPATH}" -type f \( -name '*.cmake' -o -name 'CMakeLists.txt' \) -not -path "*/3rdParty/*" -exec echo 'Formatting:' {} ';' -exec cmake-format -i {} ';'
