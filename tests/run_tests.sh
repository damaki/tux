#!/bin/bash

# Stop on first failure
set -e

# Echo commands as they are executed
set -x

# Run KAT suite
pytest kat \
    -n logical \
    --html=kat_report.html \
    --self-contained-html \
    --junitxml=kat.xml

# Run the unit tests
unit_tests/bin/unit_tests
