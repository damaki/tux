#!/bin/bash

# Stop on first failure
set -e

# Echo commands as they are executed
set -x

for subdir in $(find . -mindepth 1 -maxdepth 1 -type d)
do
    cd $subdir
    alr build
    cd ..
done