# Tux Testing

This directory contains the test suite for the Tux crypto library.

## Tests Overview

The tests are organised into the following directories:
 * `benchmark/` contains performance tests
 * `kat/` contains the "known answer tests" that test the correctness of the
   library against test vectors.
 * `support/` contains supporting code and utilities for the various test programs.
 * `unit_tests/` contains the unit tests that test the correctness of the
   library in various edge case scenarios that are not covered by the test
   vectors or proof.