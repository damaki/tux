#!/bin/sh

set -ex

script_dir=$(pwd)

function cleanup {
    find "$script_dir" -name '*.srctrace' -exec rm {} \;
    find "$script_dir" -name 'srctrace_files.txt' -exec rm {} \;
}

trap cleanup EXIT

# Build libtux in validation mode
cd ..
alr build --validation
cd tests

# Instrument Known Answer Test (KAT) suite
cd kat/programs/hash
alr clean
alr gnatcov instrument --level=stmt+mcdc --dump-trigger=atexit --projects tux.gpr
alr build --validation -- --src-subdirs=gnatcov-instr --implicit-with=gnatcov_rts_full

cd ../hkdf
alr clean
alr gnatcov instrument --level=stmt+mcdc --dump-trigger=atexit --projects tux.gpr
alr build --validation -- --src-subdirs=gnatcov-instr --implicit-with=gnatcov_rts_full

cd ../hmac
alr clean
alr gnatcov instrument --level=stmt+mcdc --dump-trigger=atexit --projects tux.gpr
alr build --validation -- --src-subdirs=gnatcov-instr --implicit-with=gnatcov_rts_full

# Run KATs
cd ../..
pytest -n 16

# Instrument & run unit tests
cd ../unit_tests
alr clean
alr gnatcov instrument --level=stmt+mcdc --dump-trigger=atexit --projects tux.gpr
alr build --validation -- --src-subdirs=gnatcov-instr --implicit-with=gnatcov_rts_full
alr exec -- bin/unit_tests

# Generate coverage report
find .. -name '*.srctrace' > srctrace_files.txt
alr gnatcov coverage \
    --annotate=html+ \
    --output-dir ../gnatcov_out \
    --level=stmt+mcdc \
    --projects tux.gpr \
    @srctrace_files.txt
