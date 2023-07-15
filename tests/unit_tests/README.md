# Unit Tests

This directory contains the unit tests which test various aspects of the
library that are not covered by proof or the KAT suite.

# Running the tests

Running the unit tests requires Alire with a GNAT native toolchain.

>:warning: The unit tests require Tux to be configured with everything enabled
> in the top-level `alire.toml`. The tests cannot be run if any cryptographic
algorithm is disabled in Tux.

To build and run the tests:
```sh
alr run
```