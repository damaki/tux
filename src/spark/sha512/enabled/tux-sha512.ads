--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
private with Interfaces;
private with Tux.Generic_Block_Streaming;

with Tux.Types; use Tux.Types;

--  @summary
--  SHA-512, SHA-384, SHA512/256, and SHA512/224 definitions and subprograms.
--
--  @description
--  This package provides an implementation of Secure Hash Algorithms (SHA)
--  384 and 512 as defined in FIPS 180-4.
--
--  @group Hash Algorithms
package Tux.SHA512 with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   type Algorithm_Kind is
     (SHA384,     --  SHA-384
      SHA512,     --  SHA-512
      SHA512_224, --  SHA-512/224
      SHA512_256  --  SHA-512/256
     );
   --  Selects the SHA-2 algorithm to use.
   --
   --  SHA-384, SHA-512, SHA-512/224, and SHA-512/256 are supported in this
   --  package.

   subtype Hash_Length_Number is Byte_Count range 28 .. 64;
   --  Represents the length of the hashes supported in this package

   Block_Length : constant Byte_Count := 128;
   --  Length of a SHA-512 block in bytes

   SHA512_224_Hash_Length : constant Hash_Length_Number := 28;
   --  Length of a SHA-512/224 hash in bytes

   SHA512_256_Hash_Length : constant Hash_Length_Number := 32;
   --  Length of a SHA-512/256 hash in bytes

   SHA384_Hash_Length     : constant Hash_Length_Number := 48;
   --  Length of a SHA-384 hash in bytes

   SHA512_Hash_Length     : constant Hash_Length_Number := 64;
   --  Length of a SHA-512 hash in bytes

   Hash_Length : constant array (Algorithm_Kind) of Hash_Length_Number :=
     (SHA384     => SHA384_Hash_Length,
      SHA512     => SHA512_Hash_Length,
      SHA512_224 => SHA512_224_Hash_Length,
      SHA512_256 => SHA512_256_Hash_Length);
   --  Lookup table of the hash lengths of each hash algorithm

   subtype SHA384_Hash is Byte_Array (1 .. SHA384_Hash_Length);
   --  Byte array subtype that can store a SHA-384 hash

   subtype SHA512_Hash is Byte_Array (1 .. SHA512_Hash_Length);
   --  Byte array subtype that can store a SHA-512 hash

   subtype SHA512_224_Hash is Byte_Array (1 .. SHA512_224_Hash_Length);
   --  Byte array subtype that can store a SHA-512/224 hash

   subtype SHA512_256_Hash is Byte_Array (1 .. SHA512_256_Hash_Length);
   --  Byte array subtype that can store a SHA-512/256 hash

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited private;
   --  Holds the state for a multi-part SHA-512 hashing session.
   --
   --  @field Algorithm Selects the hash algorithm to use (SHA-384, SHA-512,
   --                   SHA-512/224, or SHA-512/256).

   function Finished (Ctx : Context) return Boolean with
     Global => null;
   --  Query whether the SHA-512 hashing session is finished
   --
   --  @param Ctx The hashing session context.
   --  @return True if the hashing session is finished, False otherwise.

   procedure Initialize (Ctx  : out Context) with
     Global => null,
     Post   => not Finished (Ctx);
   --  Start a new multi-part SHA-512 hashing session.
   --
   --  This may be called at any time to abort an existing session and begin
   --  a new one.
   --
   --  @param Ctx The context to initialize.

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Global => null,
     Pre    => not Finished (Ctx),
     Post   => not Finished (Ctx);
   --  Process data in an ongoing SHA-512 hashing session.
   --
   --  This may be called multiple times to process large amounts of data
   --  in several steps.
   --
   --  @param Ctx The hashing session context.
   --  @param Data Buffer containing the data to process in the hashing session

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Byte_Array)
   with
     Relaxed_Initialization => Hash,
     Global  => null,
     Pre     => not Finished (Ctx) and
                Hash'Length = Hash_Length (Ctx.Algorithm),
     Post    => Finished (Ctx) and Hash'Initialized;
   --  Finish a SHA-512 hashing session and output the computed hash.
   --
   --  This procedure can be called only once per hashing session.
   --  After calling this procedure, the hashing session is finished and
   --  it is not possible to add new data to the session or (re)compute the
   --  hash. A new session can be started by calling Initialize again.
   --
   --  @param Ctx  The hashing session context.
   --  @param Hash Buffer to where the computed hash is written.

   procedure Sanitize (Ctx : out Context) with
     Global  => null,
     Post   => Finished (Ctx);
   --  Sanitize any potentially secret data held in a hashing session context.
   --
   --  @param Ctx The hashing session context to sanitize.

   ----------------------------
   -- Single-Part Operations --
   ----------------------------

   procedure Compute_Hash
     (Algorithm :     Algorithm_Kind;
      Data      :     Byte_Array;
      Hash      : out Byte_Array)
   with
     Pre => Hash'Length = Hash_Length (Algorithm);
   --  Compute the SHA-512 hash over a buffer.
   --
   --  @param Algorithm Selects the SHA-512 variant to use.
   --  @param Data Buffer containing the data to hash.
   --  @param Hash Buffer to where the computed hash is written.

   function Verify_Hash
     (Algorithm     : Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   with
     Pre => Expected_Hash'Length in 1 .. Hash_Length (Algorithm);
   --  Compute a hash over a buffer and compare the hash against an expected
   --  hash value.
   --
   --  @param Algorithm     Selects the SHA-512 variant to use.
   --  @param Data          Buffer containing the data to hash.
   --  @param Expected_Hash Buffer containing the expected hash value.
   --                       If this is smaller than the generated hash, then
   --                       only the first part of the generated hash is
   --                       compared.
   --  @return True if the generated hash exactly matches the expected hash,
   --          or False otherwise.

private
   use Interfaces;

   subtype State_Array is U64_Array (0 .. 7);
   --  SHA-512/384 state

   pragma Warnings (GNATprove, Off, "pragma ""Machine_Attribute"" ignored",
                    Reason => "Scrubbing attributes do not affect proof");

   procedure Compress_Blocks
     (State : in out State_Array;
      Blocks :        Byte_Array)
   with
     Global  => null,
     Pre     => Blocks'Length mod Block_Length = 0;
   pragma Machine_Attribute (Compress_Blocks, "strub", "internal");
   pragma Machine_Attribute (Compress_Blocks, "zero_call_used_regs", "used");
   --  Process one or more complete blocks into the SHA-2 compression function

   package Block_Streaming is new Generic_Block_Streaming
     (Internal_State_Type => State_Array,
      Process_Blocks      => Compress_Blocks,
      Block_Length        => Block_Length);

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First) is limited
   record
      State            : State_Array;
      --  The SHA-512 state

      Byte_Length_Low  : Unsigned_64;
      --  64 least significant bits of the message length (in bytes)

      Byte_Length_High : Unsigned_64;
      --  64 most significant bits of the message length (in bytes)

      Buffer           : Block_Streaming.Context;
      --  Holds any incomplete blocks of incoming data

      Finished         : Boolean;
      --  Set to True when Finish has been called

   end record;

   function Finished  (Ctx : Context) return Boolean is
     (Ctx.Finished);

end Tux.SHA512;
