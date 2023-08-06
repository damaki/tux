This directory contains a nested Alire crate configured for running GNATprove.
The purpose of this nested project is to avoid a dependency on gnatprove in the
top-level alire.toml.

See: https://alire.ada.dev/docs/#work-in-progress-dependency-overrides

To run the proofs, run the following command in this directory:
```sh
alr exec -- gnatprove -P ../tux.gpr
```
