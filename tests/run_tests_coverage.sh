#!/bin/bash

# Stop on first failure
set -e

# Echo commands as they are executed
set -x

test_crate_dir=$1
srctraces_dir=$test_crate_dir/srctraces

kat_dir=$(realpath kat)
unit_tests_exe=$(realpath "unit_tests/bin/unit_tests")

# Delete any old srctrace files
if [ -d $srctraces_dir ]
then
    rm -r $srctraces_dir
fi

# Change the CWD so that the .srctrace files are output here
mkdir -p $srctraces_dir
cd $srctraces_dir

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
alr gnatcov coverage --annotate=xcov+ --output-dir=coverage_xcov --level=stmt+mcdc --projects tux.gpr @srctraces_list.txt