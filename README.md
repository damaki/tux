# Tux

Tux is a formally verified, configurable crypto library designed for
resource-constrained embedded systems. The library is written using the SPARK
programming language with proof of absence of common runtime errors and some
functional correctness properties.

> :warning: Tux is currently in early development. Its API is considered
> unstable and breaking changes may be made at any time.

## Supported Primitives

Tux currently supports the following cryptographic primitives:
 * Hash functions:
   * SHA-1
   * SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
 * Keyed-Hash Message Authentication Code (HMAC)
 * HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

## Motivation

There are already several cryptographic libraries for embedded systems,
so why make another one?

I've used various crypto libraries on several resource-constrained embedded
system projects (with as little as a few tens of kilobytes of memory).
While some crypto libraries met my requirements better than others, there were
some aspects to their design that complicated their use in my projects,
for example:
 * use of dynamic memory allocation, which increased memory requirements
   and added complexity and extra failure scenarios (e.g. out-of-memory conditions).
 * difficulty in taking advantage of hardware crypto acceleration without
   modifying the library sources, which required the additional burden of
   maintaining patches to keep the library up to date.
 * lack of configurability for different performance/resource usage scenarios
   to tune the library for the project's needs, such as trading off speed
   against code size.

### Objectives

This project is an attempt to design a high-assurance crypto library that
meets these objectives:

* The library is written in the SPARK programming language with a formal
  proof that the library contains no run-time errors that could lead to
  security vulnerabilities, for example buffer overflows.
* The library provides bindings to other languages, such as C.
* The library has a small code footprint.
* The library has competitive performance compared to other similar libraries.
* The library can be used in "bare metal" environments with little (or no)
  standard library support. In particular, the library does not use dynamic
  memory (heap) allocation nor the secondary stack.
* The library can be configured to trade off between speed, code size, and
  other attributes depending on the user's requirements. Unused parts of the
  library can be disabled to reduce code size.
* The API supports multi-part operations to allow large messages to be
  processed in small fragments, instead of requiring the entire message in
  one (potentially large) buffer.
* The library is amenable to static stack analysis.
* Users can easily extend this crate to replace parts of the library with hardware
  accelerated implementations.

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
      This variable has no effect when `SHA256_Enabled` is `false`.
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
      This variable has no effect when `SHA512_Enabled` is `false`.
      <ul>
        <li><tt>"Speed"</tt> selects the implementation optimised for speed.</li>
        <li><tt>"Size"</tt> selects the implementation optimised for small code size.</li></li>
      </ul>
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