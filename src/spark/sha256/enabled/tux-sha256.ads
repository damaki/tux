--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
private with Interfaces;
private with Tux.Generic_Block_Streaming;

with Tux.Types; use Tux.Types;

--  @summary
--  SHA-256 and SHA-224 definitions and subprograms.
--
--  @description
--  This package provides an implementation of Secure Hash Algorithms (SHA)
--  224 and 256 as defined in FIPS 180-4.
--
--  @group Hash Algorithms
package Tux.SHA256 with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   type Algorithm_Kind is
     (SHA224, --  SHA-224
      SHA256  --  SHA-256
     );
   --  Selects the SHA-2 algorithm to use.
   --
   --  SHA-224 and SHA-256 are supported in this package.

   subtype Hash_Length_Number is Byte_Count range 28 .. 32;
   --  Represents the length of the hashes supported in this package

   Block_Length : constant Byte_Count := 64;
   --  Length of a SHA-256 block in bytes

   SHA224_Hash_Length : constant Hash_Length_Number := 28;
   --  Length of a SHA-224 hash in bytes

   SHA256_Hash_Length : constant Hash_Length_Number := 32;
   --  Length of a SHA-256 hash in bytes

   Hash_Length : constant array (Algorithm_Kind) of Hash_Length_Number :=
     (SHA224 => SHA224_Hash_Length,
      SHA256 => SHA256_Hash_Length);
   --  Lookup table of the hash lengths of each hash algorithm

   subtype SHA224_Hash is Byte_Array (1 .. SHA224_Hash_Length);
   --  Byte array subtype that can store a SHA-224 hash

   subtype SHA256_Hash is Byte_Array (1 .. SHA256_Hash_Length);
   --  Byte array subtype that can store a SHA-256 hash

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited private;
   --  Holds the state for a multi-part SHA-256 hashing session.
   --
   --  @field Algorithm Selects the hash algorithm to use (SHA-224 or SHA-256).

   function Finished (Ctx : Context) return Boolean with
     Global => null;
   --  Query whether the SHA-256 hashing session is finished
   --
   --  @param Ctx The hashing session context.
   --  @return True if the hashing session is finished, False otherwise.

   procedure Initialize (Ctx : out Context) with
     Global => null,
     Post   => not Finished (Ctx);
   --  Start a new multi-part SHA-256 hashing session.
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
   --  Process data in an ongoing SHA-256 hashing session.
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
     Global => null,
     Pre    => not Finished (Ctx) and
               Hash'Length = Hash_Length (Ctx.Algorithm),
     Post   => Finished (Ctx) and Hash'Initialized;
   --  Finish a SHA-256 hashing session and output the computed hash.
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
     Post => Finished (Ctx);
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
     Global => null,
     Pre    => Hash'Length = Hash_Length (Algorithm);
   --  Compute the SHA-256 hash over a buffer.
   --
   --  @param Algorithm Selects the SHA-256 variant to use.
   --  @param Data Buffer containing the data to hash.
   --  @param Hash Buffer to where the computed hash is written.

   function Verify_Hash
     (Algorithm     : Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   with
     Global => null,
     Pre    => Expected_Hash'Length in 1 .. Hash_Length (Algorithm);
   --  Compute a hash over a buffer and compare the hash against an expected
   --  hash value.
   --
   --  @param Algorithm     Selects the SHA-256 variant to use.
   --  @param Data          Buffer containing the data to hash.
   --  @param Expected_Hash Buffer containing the expected hash value.
   --                       If this is smaller than the generated hash, then
   --                       only the first part of the generated hash is
   --                       compared.
   --  @return True if the generated hash exactly matches the expected hash,
   --          or False otherwise.

private
   use Interfaces;

   subtype State_Array is U32_Array (0 .. 7);
   --  SHA-256/224 state

   pragma Warnings (GNATprove, Off, "pragma ""Machine_Attribute"" ignored",
                    Reason => "Scrubbing attributes do not affect proof");

   procedure Compress_Blocks
     (State  : in out State_Array;
      Blocks :        Byte_Array)
   with
     Global  => null,
     Pre     => Blocks'Length mod 64 = 0;
   pragma Machine_Attribute (Compress_Blocks, "strub", "internal");
   pragma Machine_Attribute (Compress_Blocks, "zero_call_used_regs", "used");
   --  Process one or more complete blocks into the SHA-2 compression function

   package Block_Streaming is new Generic_Block_Streaming
     (Internal_State_Type => State_Array,
      Process_Blocks      => Compress_Blocks,
      Block_Length        => Block_Length);

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First) is limited
   record
      State           : State_Array;
      --  The SHA-256/224 state

      Bytes_Processed : Unsigned_64;
      --  The total message length in bytes

      Buffer          : Block_Streaming.Context;
      --  Holds any incomplete blocks of incoming data

      Finished        : Boolean;
      --  True when the hashing session is finished
   end record;

   function Finished  (Ctx : Context) return Boolean is
     (Ctx.Finished);

end Tux.SHA256;
