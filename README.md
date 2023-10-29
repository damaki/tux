# Tux

Tux is a formally verified, configurable crypto library designed for
resource-constrained embedded systems. The library is written using the SPARK
programming language with proof of absence of common runtime errors and some
functional correctness properties.

## Project Status

Tux is currently in the initial project setup phase. A small number of
cryptographic primitives have already been implemented, but the documentation
and verification processes are not yet fully set up. The API is considered
unstable until the 1.0.0 release and breaking changes are likely until then.


## Supported Primitives

Tux currently supports the following cryptographic primitives:
 * Hash functions:
   * SHA-1
   * SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
   * SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
 * eXtendable Output Functions (XOF):
   * SHAKE128, SHAKE256
 * Keyed-Hash Message Authentication Code (HMAC)
 * HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

## Motivation

There are already several cryptographic libraries for embedded systems,
so why make another one?

I've used various crypto libraries on several resource-constrained embedded
projects with as little as a few tens of kilobytes of memory.
While some crypto libraries met my requirements better than others, there were
some aspects to their design that complicated their use in my projects,
for example:
 * use of unsafe programming languages (C in particular).
 * use of dynamic memory allocation, which increased memory requirements
   and added complexity and extra failure scenarios (e.g. out-of-memory
   conditions).
 * difficulty in taking advantage of hardware crypto acceleration without
   modifying the library sources, which required the additional burden of
   maintaining patches to keep the library up to date.
 * lack of configurability for different performance/resource usage scenarios
   to tune the library for the project's needs, such as trading off speed
   against code size.

This project aims to address these issues and more.

## Objectives

### Assurance

The library is written in the SPARK programming language with a formal
proof that the library contains no run-time errors or undefined behaviours that
could lead to security vulnerabilities such as buffer overruns, integer
overflow, etc.

The library has an extensive automated test suite to verify its correctness
for things that are not covered by proof.

### Configurability

The library can be configured to disable unused algorithms (thereby saving code
space) and to select different implementations of cryptographic primitives to,
for example, trade off between performance and code size.

### Usability

The library has an easy to use API and provides bindings to other languages
such as C. In particular, the library supports multi-part operations to allow
large messages to be processed in small fragments, instead of requiring the
entire message to be processed in a single (potentially very large) buffer.

### Performance

The library has competitive performance compared to other similar libraries
and with a small code footprint.

### Embedded Systems

The library is designed to be usable in resource-constrained embedded systems.
In particular:
* The library can be run in "bare metal" environments with little (or no)
  standard library support.
* The library does not use heap allocation nor the secondary stack.
* The library is amenable to static stack analysis to determine the worst-case
  stack usage.
* Users can easily extend this crate to replace parts of the library with
  hardware accelerated implementations without needing to modify the crate
  itself.

## Using Tux

Tux is built using [Alire](https://alire.ada.dev). It's not released into the
Alire index (yet), but you can include Tux in your project by downloading
this repository and adding a pin in your project's `alire.toml`:
```toml
[[depends-on]]
tux = "*"

[[pins]]
tux = { path = "path/to/tux" }
```

## Configuration

Tux is configured through Alire's crate configuration. The configuration
variables supported by Tux are:

<table>
  <thead>
    <th>Variable</th>
    <th>Values</th>
    <th>Default</th>
    <th>Description</th>
  </thead>
  <tr>
    <td><tt>SHA1_Enabled</tt></td>
    <td>
      <tt>true</tt><br/>
      <tt>false</tt><br/>
    </td>
    <td><tt>true</tt></td>
    <td>
      Enables/disables support for SHA-1.
    </td>
  </tr>
  <tr>
    <td><tt>SHA256_Enabled</tt></td>
    <td>
      <tt>true</tt><br/>
      <tt>false</tt><br/>
    </td>
    <td><tt>true</tt></td>
    <td>
      Enables/disables support for SHA-256 and SHA-224.
    </td>
  </tr>
  <tr>
    <td><tt>SHA256_Backend</tt></td>
    <td>
      <tt>"Speed"</tt><br/>
      <tt>"Size"</tt><br/>
    </td>
    <td><tt>"Speed"</tt></td>
    <td>
      Configures the SHA-256 and SHA-224 backend.
      This variable has no effect when <tt>SHA256_Enabled</tt> is <tt>false</tt>.
      <ul>
        <li><tt>"Speed"</tt> selects the implementation optimised for speed.</li>
        <li><tt>"Size"</tt> selects the implementation optimised for small code size.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td><tt>SHA512_Enabled</tt></td>
    <td>
      <tt>true</tt><br/>
      <tt>false</tt><br/>
    </td>
    <td><tt>true</tt></td>
    <td>
      Enables/disables support for SHA-512, SHA-384, SHA-512/224, and SHA-512/256.
    </td>
  </tr>
  <tr>
    <td><tt>SHA512_Backend</tt></td>
    <td>
      <tt>"Speed"</tt><br/>
      <tt>"Size"</tt><br/>
    </td>
    <td><tt>"Speed"</tt></td>
    <td>
      Configures the SHA-512, SHA-384, SHA-512/224, and SHA-512/256 backend.
      This variable has no effect when <tt>SHA512_Enabled</tt> is <tt>false</tt>.
      <ul>
        <li><tt>"Speed"</tt> selects the implementation optimised for speed.</li>
        <li><tt>"Size"</tt> selects the implementation optimised for small code size.</li></li>
      </ul>
    </td>
  </tr>
  <tr>
    <td><tt>SHA3_Enabled</tt></td>
    <td>
      <tt>true</tt><br/>
      <tt>false</tt><br/>
    </td>
    <td><tt>true</tt></td>
    <td>
      Enables/disables support for SHA-3 hash functions (SHA3-224, SHA3-256, SHA3-384, and SHA3-512).
    </td>
  </tr>
  <tr>
    <td><tt>SHAKE_Enabled</tt></td>
    <td>
      <tt>true</tt><br/>
      <tt>false</tt><br/>
    </td>
    <td><tt>true</tt></td>
    <td>
      Enables/disables support for the SHAKE128 and SHAKE256 eXtendable Output Functions (XOF).
    </td>
  </tr>
  <tr>
    <td><tt>Self_Tests_Enabled</tt></td>
    <td>
      <tt>true</tt><br/>
      <tt>false</tt><br/>
    </td>
    <td><tt>true</tt></td>
    <td>
      Enables/disables self-test subprograms.
    </td>
  </tr>
</table>

For example, to select the SHA-256 implementation that is optimised for code
size, add the following to your project's `alire.toml`:

```toml
[configuration.values]
tux.SHA256_Backend = "Size"
```