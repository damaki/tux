# Tux Testing

This directory contains the test suite for the Tux crypto library.

## Tests Overview

The tests are organised into the following directories:
 * `benchmark/` contains a benchmark program for performance tests
 * `kat/` contains the "known answer tests" that test the library against test vectors.
 * `support/` contains supporting code and utilities for the various test programs.
 * `unit_tests/` contains the unit tests that test the correctness of the
   library in various edge case scenarios that are not covered by the test
   vectors or proof.

## Prerequisites

To run the tests you will need:
 * [Alire](https://alire.ada.dev/)
 * Python 3
 * the Python dependencies listed in requirements.txt.

## Running the Tests

To build and run the tests in the default configuration:
```sh
python make_build_crate.py --output-dir test_crate
cd test_crate
alr build
cd ..
run_tests.sh test_crate
```

### Testing Different Configurations

Use `make_build_crate.py` to set the Tux crate configuration values that should
be used for testing. For example, to run the tests over the SHA-256
implementation optimized for size, pass `--sha256-backend=Size` to
`make_build_crate.py`:
```sh
python make_build_crate.py --output-dir test_crate --sha256-backend=Size
```

Use `python make_build_crate.py --help` to see the list of available options
and their permitted values.

### Generating Coverage Reports

To build & run the instrumented test suite for code coverage:
```sh
python make_build_crate.py --output-dir test_crate --coverage
./instrumented_build.sh test_crate
run_tests_coverage.sh test_crate
```

The GNATcoverage HTML report will be generated in `test_crate/coverage_html/`.