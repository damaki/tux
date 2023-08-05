#!/bin/sh

set -ex

# Build libtux in validation mode
cd ..
alr build --validation
cd tests

# Instrument Known Answer Test (KAT) suite
cd kat/programs/hash
alr build --validation

cd ../hkdf
alr build --validation

cd ../hmac
alr build --validation

# Run KATs
cd ../..
pytest -n 16

# Instrument & run unit tests
cd ../unit_tests
alr build --validation
alr exec -- bin/unit_tests
