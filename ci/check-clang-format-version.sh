#!/bin/sh
EXPECTED_VERSION="18.1.6"

# Get the installed clang-format version
INSTALLED_VERSION=$(clang-format --version | grep -oE '[0-9]+(\.[0-9]+)+')

if [ "$INSTALLED_VERSION" != "$EXPECTED_VERSION" ]; then
    echo "Error: clang-format version $INSTALLED_VERSION found, but $EXPECTED_VERSION is required."
    exit 1
fi

exit 0
