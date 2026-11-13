#!/bin/sh
# Generates a universal requirements.txt with hashes next to every requirements .in file.
# Edit the versions in the .in files and run this script from the repository root (requires uv).
# Extra arguments are passed to uv, e.g. "--upgrade" to also refresh transitive dependencies.
set -eu

for in_file in Tests/ExamplesTest/requirements.in ci/run_tests/requirements.in ci/requirements/*.in; do
    uv pip compile --universal --generate-hashes "$in_file" -o "${in_file%.in}.txt" --python-version 3.9.1 "$@"
done
