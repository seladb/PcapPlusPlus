#!/bin/bash
set -e

cd build
make
ctest --verbose
