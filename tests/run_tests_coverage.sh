#!/bin/bash

# Stop on first failure
set -e

# Echo commands as they are executed
set -x

test_crate_dir=$1

kat_dir=$(realpath kat)
unit_tests_exe=$(realpath "unit_tests/bin/unit_tests")

# Change the CWD so that the .srctrace files are output here
mkdir -p $test_crate_dir/srctraces
cd $test_crate_dir/srctraces

# Run KAT suite
pytest $kat_dir \
    -n logical \
    --html="$test_crate_dir/kat_report.html" \
    --self-contained-html \
    --junitxml="$test_crate_dir/kat.xml"

# Run the unit tests
$unit_tests_exe

cd ..

# Generate a listing file of all srctraces
find . -type f -name "*.srctrace" > srctraces_list.txt

# Generate the coverage reports
alr gnatcov coverage --annotate=html+ --output-dir=coverage_html --level=stmt+mcdc --projects tux.gpr @srctraces_list.txt
alr gnatcov coverage --annotate=xcov+ --output-dir=coverage_html --level=stmt+mcdc --projects tux.gpr @srctraces_list.txt