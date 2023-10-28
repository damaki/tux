--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux_Config; use Tux_Config;
with Tux.Types;  use Tux.Types;

with Tux.SHA1;
with Tux.SHA256;
with Tux.SHA512;
with Tux.SHA3;

--  @summary
--  Wrapper around hash functions.
--
--  @description
--  This package provides a convenient wrapper around the supported hash
--  functions, allowing run-time selection of hash algorithms.
--
--  @group Hash Algorithms
package Tux.Hashing with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   ------------------------
   -- Hash Algorithm IDs --
   ------------------------

   type Algorithm_Kind is
     (SHA1,       --  SHA-1
      SHA224,     --  SHA-224
      SHA256,     --  SHA-256
      SHA384,     --  SHA-384
      SHA512,     --  SHA-512
      SHA512_224, --  SHA-512/224
      SHA512_256, --  SHA-512/256
      SHA3_224,   --  SHA3-224
      SHA3_256,   --  SHA3-256
      SHA3_384,   --  SHA3-384
      SHA3_512    --  SHA3-512
     );
   --  The set of hash algorithms that are supported in this package.
   --
   --  Note that some hash functions might be disabled via the crate
   --  configuration. The set of enabled hash algorithms is represented
   --  by the Enabled_Algorithm_Kind type.

   --------------------------------
   -- Enabled Hash Algorithm IDs --
   --------------------------------

   SHA1_Disabled : constant Boolean := not Tux_Config.SHA1_Enabled;
   --  @private

   SHA256_Disabled : constant Boolean := not Tux_Config.SHA256_Enabled;
   --  @private

   SHA512_Disabled : constant Boolean := not Tux_Config.SHA512_Enabled;
   --  @private

   SHA3_Disabled : constant Boolean := not Tux_Config.SHA3_Enabled;
   --  @private

   pragma Warnings
     (Off, "predicate is redundant",
      Reason => "Predicate depends on the crate configuration");

   subtype Enabled_Algorithm_Kind is Algorithm_Kind with
     Dynamic_Predicate =>
       ((if SHA1_Disabled then Enabled_Algorithm_Kind /= SHA1)
        and
        (if SHA256_Disabled then Enabled_Algorithm_Kind not in SHA224 | SHA256)
        and
        (if SHA512_Disabled then Enabled_Algorithm_Kind not in
                                   SHA384 | SHA512 | SHA512_224 | SHA512_256)
        and
        (if SHA3_Disabled then Enabled_Algorithm_Kind not in
                                 SHA3_224 | SHA3_256 | SHA3_384 | SHA3_512));
   --  The set of hash algorithms that are enabled in the crate configuration.
   --
   --  The predicate on this type prohibits all hash algorithms that are
   --  disabled in the crate configuration.

   pragma Warnings (On);

   ------------------------------
   -- Hash Function Attributes --
   ------------------------------

   subtype Hash_Length_Number  is Byte_Count range 20 .. 64;
   --  Represents the length of the hashes output by a hash function

   subtype Block_Length_Number is Byte_Count range 56 .. 144;
   --  Represents the block size of a hash function

   type Hash_Length_Table  is array (Algorithm_Kind) of Hash_Length_Number;
   --  Maps a hash algorithm enum to its corresponding hash length

   type Block_Length_Table is array (Algorithm_Kind) of Block_Length_Number;
   --  Maps a hash algorithm enum to its corresponding block length

   Hash_Length : constant Hash_Length_Table :=
     (SHA1       => Tux.SHA1.SHA1_Hash_Length,
      SHA224     => Tux.SHA256.SHA224_Hash_Length,
      SHA256     => Tux.SHA256.SHA256_Hash_Length,
      SHA384     => Tux.SHA512.SHA384_Hash_Length,
      SHA512     => Tux.SHA512.SHA512_Hash_Length,
      SHA512_224 => Tux.SHA512.SHA512_224_Hash_Length,
      SHA512_256 => Tux.SHA512.SHA512_256_Hash_Length,
      SHA3_224   => Tux.SHA3.SHA3_224_Hash_Length,
      SHA3_256   => Tux.SHA3.SHA3_256_Hash_Length,
      SHA3_384   => Tux.SHA3.SHA3_384_Hash_Length,
      SHA3_512   => Tux.SHA3.SHA3_512_Hash_Length);
   --  Lookup table of the hash lengths of each hash algorithm

   Block_Length : constant Block_Length_Table :=
     (SHA1       => Tux.SHA1.Block_Length,
      SHA224     => Tux.SHA256.Block_Length,
      SHA256     => Tux.SHA256.Block_Length,
      SHA384     => Tux.SHA512.Block_Length,
      SHA512     => Tux.SHA512.Block_Length,
      SHA512_224 => Tux.SHA512.Block_Length,
      SHA512_256 => Tux.SHA512.Block_Length,
      SHA3_224   => Tux.SHA3.SHA3_224_Block_Length,
      SHA3_256   => Tux.SHA3.SHA3_256_Block_Length,
      SHA3_384   => Tux.SHA3.SHA3_384_Block_Length,
      SHA3_512   => Tux.SHA3.SHA3_512_Block_Length);
   --  Lookup table of the block size of each hash algorithm

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Algorithm : Enabled_Algorithm_Kind) is limited private;
   --  Holds the state for a multi-part hashing session.
   --
   --  @field Algorithm Selects the hash algorithm to use.

   function Finished (Ctx : Context) return Boolean;
   --  Query whether the hashing session is finished
   --
   --  @param Ctx The hashing session context.
   --  @return True if the hashing session is finished, False otherwise.

   procedure Initialize (Ctx : out Context) with
     Relaxed_Initialization => Ctx,
     Post => not Finished (Ctx) and Ctx'Initialized;
   --  Start a new multi-part hashing session.
   --
   --  This may be called at any time to abort an existing session and begin
   --  a new one.
   --
   --  @param Ctx The context to initialize.

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Pre  => not Finished (Ctx),
     Post => not Finished (Ctx);
   --  Process data in an ongoing hashing session.
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
     Pre  => (not Finished (Ctx)
              and Hash'Length = Hash_Length (Ctx.Algorithm)),
     Post => Finished (Ctx) and Hash'Initialized;
   --  Finish a hashing session and output the computed hash.
   --
   --  This procedure can be called only once per hashing session.
   --  After calling this procedure, the hashing session is finished and
   --  it is not possible to add new data to the session or (re)compute the
   --  hash. A new session can be started by calling Initialize again.
   --
   --  @param Ctx  The hashing session context.
   --  @param Hash Buffer to where the computed hash is written.

   procedure Finish_And_Verify
     (Ctx           : in out Context;
      Expected_Hash :        Byte_Array;
      Valid         :    out Boolean)
   with
     Pre  => (not Finished (Ctx)
              and Expected_Hash'Length in 1 .. Hash_Length (Ctx.Algorithm)),
     Post => Finished (Ctx);
   --  Finish a hashing session and compare the generated hash against an
   --  expected hash value.
   --
   --  This procedure can be called only once per hashing session.
   --  After calling this procedure, the hashing session is finished and
   --  it is not possible to add new data to the session or (re)compute the
   --  hash. A new session can be started by calling Initialize again.
   --
   --  @param Ctx The hashing session context.
   --  @param Expected_Hash Buffer containing the expected hash value.
   --                       If this is smaller than the generated hash, then
   --                       only the first part of the generated hash is
   --                       compared.
   --  @param Valid Set to True if the computed hash exactly matches the
   --               expected hash, or False otherwise.

   procedure Sanitize (Ctx : out Context) with
     Relaxed_Initialization => Ctx,
     Post => Finished (Ctx) and Ctx'Initialized;
   --  Sanitize any potentially secret data held in a hashing session context.
   --
   --  @param Ctx The hashing session context to sanitize.

   ----------------------------
   -- Single-Part Operations --
   ----------------------------

   procedure Compute_Hash
     (Algorithm :     Enabled_Algorithm_Kind;
      Data      :     Byte_Array;
      Hash      : out Byte_Array)
   with
     Pre => Hash'Length = Hash_Length (Algorithm);
   --  Compute a hash over a buffer.
   --
   --  @param Algorithm Selects the hash algorithm to use.
   --  @param Data      Buffer containing the data to hash.
   --  @param Hash      Buffer to where the computed hash is written.
   --                   The length of this buffer must exactly match the length
   --                   of the hashes output by the selected Algorithm.

   function Verify_Hash
     (Algorithm     : Enabled_Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   with
     Pre => Expected_Hash'Length in 1 .. Hash_Length (Algorithm);
   --  Compute a hash over a buffer and compare the hash against an expected
   --  hash value.
   --
   --  @param Algorithm Selects the hash algorithm to use.
   --  @param Data      Buffer containing the data to hash.
   --  @param Expected_Hash Buffer containing the expected hash value.
   --                       If this is smaller than the generated hash, then
   --                       only the first part of the generated hash is
   --                       compared.
   --  @return True if the generated hash exactly matches the expected hash,
   --          or False otherwise.

private

   type Context (Algorithm : Enabled_Algorithm_Kind) is limited record
      case Algorithm is
         when SHA1 =>
            SHA1_Ctx : Tux.SHA1.Context;
         when SHA224 =>
            SHA224_Ctx : Tux.SHA256.Context (Tux.SHA256.SHA224);
         when SHA256 =>
            SHA256_Ctx : Tux.SHA256.Context (Tux.SHA256.SHA256);
         when SHA384 =>
            SHA384_Ctx : Tux.SHA512.Context (Tux.SHA512.SHA384);
         when SHA512 =>
            SHA512_Ctx : Tux.SHA512.Context (Tux.SHA512.SHA512);
         when SHA512_224 =>
            SHA512_224_Ctx : Tux.SHA512.Context (Tux.SHA512.SHA512_224);
         when SHA512_256 =>
            SHA512_256_Ctx : Tux.SHA512.Context (Tux.SHA512.SHA512_256);
         when SHA3_224 =>
            SHA3_224_Ctx : Tux.SHA3.Context (Tux.SHA3.SHA3_224);
         when SHA3_256 =>
            SHA3_256_Ctx : Tux.SHA3.Context (Tux.SHA3.SHA3_256);
         when SHA3_384 =>
            SHA3_384_Ctx : Tux.SHA3.Context (Tux.SHA3.SHA3_384);
         when SHA3_512 =>
            SHA3_512_Ctx : Tux.SHA3.Context (Tux.SHA3.SHA3_512);
      end case;
   end record;

end Tux.Hashing;
