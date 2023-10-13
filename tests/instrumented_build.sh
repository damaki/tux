#!/bin/bash

# Stop on first failure
set -e

# Echo commands as they are executed
set -x

build_crate_dir=$1

project_files=("unit_tests/*.gpr" "kat/programs/*/*.gpr")

abs_project_files=$(realpath ${project_files[@]})

cd $build_crate_dir

for proj_file in $abs_project_files
do
    alr exec -- gnatcov instrument \
        -P "$proj_file" \
        --level=stmt+mcdc \
        --dump-trigger=atexit \
        --projects tux.gpr
done

alr build -- --src-subdirs=gnatcov-instr --implicit-with=gnatcov_rts_full