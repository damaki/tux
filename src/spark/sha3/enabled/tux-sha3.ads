--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
private with Tux.Sponge_Keccak_1600_24;

with Tux.Types; use Tux.Types;

--  @summary
--  SHA-256 and SHA-224 definitions and subprograms.
--
--  @description
--  This package provides an implementation of Secure Hash Algorithms (SHA)
--  224 and 256 as defined in FIPS 180-4.
--
--  @group Hash Algorithms
package Tux.SHA3 with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   type Algorithm_Kind is
     (SHA3_224, --  SHA3-224
      SHA3_256, --  SHA3-256
      SHA3_384, --  SHA3-384
      SHA3_512  --  SHA3-512
     );
   --  Selects the SHA-3 algorithm to use

   subtype Hash_Length_Number is Byte_Count range 28 .. 64;
   --  Represents the length of the hashes supported in this package

   SHA3_224_Block_Length : constant Byte_Count := (1600 - (224 * 2)) / 8;
   --  Length of a SHA3-224 block in bytes

   SHA3_256_Block_Length : constant Byte_Count := (1600 - (256 * 2)) / 8;
   --  Length of a SHA3-224 block in bytes

   SHA3_384_Block_Length : constant Byte_Count := (1600 - (384 * 2)) / 8;
   --  Length of a SHA3-224 block in bytes

   SHA3_512_Block_Length : constant Byte_Count := (1600 - (512 * 2)) / 8;
   --  Length of a SHA3-224 block in bytes

   SHA3_224_Hash_Length : constant Hash_Length_Number := 28;
   --  Length of a SHA3-224 hash in bytes

   SHA3_256_Hash_Length : constant Hash_Length_Number := 32;
   --  Length of a SHA3-224 hash in bytes

   SHA3_384_Hash_Length : constant Hash_Length_Number := 48;
   --  Length of a SHA3-224 hash in bytes

   SHA3_512_Hash_Length : constant Hash_Length_Number := 64;
   --  Length of a SHA3-224 hash in bytes

   Hash_Length : constant array (Algorithm_Kind) of Hash_Length_Number :=
     (SHA3_224 => SHA3_224_Hash_Length,
      SHA3_256 => SHA3_256_Hash_Length,
      SHA3_384 => SHA3_384_Hash_Length,
      SHA3_512 => SHA3_512_Hash_Length);
   --  Lookup table of the hash lengths of each hash algorithm

   subtype SHA3_224_Hash is Byte_Array (1 .. SHA3_224_Hash_Length);
   --  Byte array subtype that can store a SHA-224 hash

   subtype SHA3_256_Hash is Byte_Array (1 .. SHA3_256_Hash_Length);
   --  Byte array subtype that can store a SHA-256 hash

   subtype SHA3_384_Hash is Byte_Array (1 .. SHA3_384_Hash_Length);
   --  Byte array subtype that can store a SHA-384 hash

   subtype SHA3_512_Hash is Byte_Array (1 .. SHA3_512_Hash_Length);
   --  Byte array subtype that can store a SHA-512 hash

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited private;
   --  Holds the state for a multi-part SHA-3 hashing session.
   --
   --  @field Algorithm Selects the hash algorithm to use.

   function Finished (Ctx : Context) return Boolean;
   --  Query whether the SHA-3 hashing session is finished
   --
   --  @param Ctx The hashing session context.
   --  @return True if the hashing session is finished, False otherwise.

   procedure Initialize (Ctx : out Context) with
     Inline,
     Relaxed_Initialization => Ctx,
     Post => Ctx'Initialized and not Finished (Ctx);
   --  Start a new multi-part SHA-3 hashing session.
   --
   --  This may be called at any time to abort an existing session and begin
   --  a new one.
   --
   --  @param Ctx The context to initialize.

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Inline,
     Pre  => not Finished (Ctx),
     Post => not Finished (Ctx);
   --  Process data in an ongoing SHA-3 hashing session.
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
     Inline,
     Relaxed_Initialization => Hash,
     Pre    => not Finished (Ctx) and
               Hash'Length = Hash_Length (Ctx.Algorithm),
     Post   => Finished (Ctx) and Hash'Initialized;
   --  Finish a SHA-3 hashing session and output the computed hash.
   --
   --  This procedure can be called only once per hashing session.
   --  After calling this procedure, the hashing session is finished and
   --  it is not possible to add new data to the session or (re)compute the
   --  hash. A new session can be started by calling Initialize again.
   --
   --  @param Ctx  The hashing session context.
   --  @param Hash Buffer to where the computed hash is written.

   procedure Sanitize (Ctx : out Context) with
     Inline,
     Relaxed_Initialization => Ctx,
     Post => Ctx'Initialized and Finished (Ctx);
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
     Pre    => Hash'Length = Hash_Length (Algorithm);
   --  Compute the SHA-3 hash over a buffer.
   --
   --  @param Algorithm Selects the SHA-3 variant to use.
   --  @param Data Buffer containing the data to hash.
   --  @param Hash Buffer to where the computed hash is written.

   function Verify_Hash
     (Algorithm     : Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   with
     Pre    => Expected_Hash'Length in 1 .. Hash_Length (Algorithm);
   --  Compute a hash over a buffer and compare the hash against an expected
   --  hash value.
   --
   --  @param Algorithm     Selects the SHA-3 variant to use.
   --  @param Data          Buffer containing the data to hash.
   --  @param Expected_Hash Buffer containing the expected hash value.
   --                       If this is smaller than the generated hash, then
   --                       only the first part of the generated hash is
   --                       compared.
   --  @return True if the generated hash exactly matches the expected hash,
   --          or False otherwise.

private
   use Tux.Sponge_Keccak_1600_24;

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited record
      case Algorithm is
         when SHA3_224 =>
            Ctx_224 : Sponge_Keccak_1600_24.Context (SHA3_224_Block_Length);
         when SHA3_256 =>
            Ctx_256 : Sponge_Keccak_1600_24.Context (SHA3_256_Block_Length);
         when SHA3_384 =>
            Ctx_384 : Sponge_Keccak_1600_24.Context (SHA3_384_Block_Length);
         when SHA3_512 =>
            Ctx_512 : Sponge_Keccak_1600_24.Context (SHA3_512_Block_Length);
      end case;
   end record;

   function Finished (Ctx : Context) return Boolean is
     (case Ctx.Algorithm is
         when SHA3_224 => Current_State (Ctx.Ctx_224) = Squeezing,
         when SHA3_256 => Current_State (Ctx.Ctx_256) = Squeezing,
         when SHA3_384 => Current_State (Ctx.Ctx_384) = Squeezing,
         when SHA3_512 => Current_State (Ctx.Ctx_512) = Squeezing);

end Tux.SHA3;
