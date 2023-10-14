#!/bin/bash

# Stop on first failure
set -e

# Echo commands as they are executed
set -x

for subdir in $(find . -mindepth 1 -maxdepth 1 -type d)
do
    cd $subdir
    # Build in validation mode to enable style checking
    alr build --validation
    cd ..
done