#!/bin/sh
set -e

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "${SCRIPT}")
ROOTPATH=${SCRIPTPATH}/..

find "${ROOTPATH}" \( -name '*.cmake' -o -name 'CMakeLists.txt' \) -exec echo 'Formatting:' {} ';' -exec cmake-format -i {} ';'
