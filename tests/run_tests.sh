#!/bin/bash

# Stop on first failure
set -e

# Echo commands as they are executed
set -x

test_crate_dir=$1

# Run KAT suite
pytest kat \
    -n logical \
    --html="$test_crate_dir/kat_report.html" \
    --self-contained-html \
    --junitxml="$test_crate_dir/kat.xml"

# Run the unit tests
unit_tests/bin/unit_tests
