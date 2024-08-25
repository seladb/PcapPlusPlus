#!/bin/bash

if [ -z "${SAMPLES}" ]; then
    SAMPLES=regression_samples
fi
if [ -z "${BINARY}" ]; then
    BINARY=../Bin/FuzzTarget
fi

ERR_CODE=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

for sample in $(ls ${SAMPLES}); do
    echo -n "Running sample $sample..."
    "${BINARY}" "$SAMPLES/$sample" &> /dev/null && echo -e "${GREEN}[OK]${NC}" || { FAILED=True && echo -e "${RED}[FAIL]${NC}"; }
done

if [[ ! -z $FAILED ]]; then
    ERR_CODE=1
fi

exit $ERR_CODE
