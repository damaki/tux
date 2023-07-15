# Known Answer Tests (KAT)

This directory contains the Known Answer Tests (KAT) which verifies each
of the supported cryptographic algorithms against test vectors.

The KAT test suite consists of the following parts:
 * The `programs` directory contains the Ada test driver programs that wrap the library.
   They receive the input data via the command line and/or standard input,
   call the appropriate crypto algorithm in the library, then print the result
   to the standard output.
 * The `test_vectors` directory contains the test vector files for the supported
   algorithms.
 * The Python scripts in this directory handle the running of the tests using PyTest.
   They load the test vector files, invoke the test driver programs, then check
   the computed result against the test vectors.

# Running the tests

## Prerequisites

Running these tests requires:
 * Alire with a GNAT native toolchain
 * Python >= 3.8
 * pytest
 * pytest-xdist (optional)

You can install pytest and pytest-xdist via Python's `pip`:
```sh
pip install -m pytest pytest-xdist
```

## Building the test programs

The test programs need to be built before running the tests.
The `build-programs.sh` script can be used to build these programs.
```sh
./build-programs.sh
```

## Running the tests

After the test programs are built, the tests can be run using pytest:
```sh
pytest
```

If pytest-xdist is installed, then the tests can be run in parallel.
For example, to use all logical cores:
```sh
pytest -n logical
```

Specifying a specific Python file will run only the tests in that file.
For example, to run only the HMAC tests:
```sh
pytest test_hmac.py
```