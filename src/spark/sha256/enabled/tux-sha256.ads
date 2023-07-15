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
package Tux.SHA256 with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   type Algorithm_Kind is (SHA224, SHA256);

   subtype Hash_Length_Number is Byte_Count range 28 .. 32;

   Block_Length : constant Byte_Count := 64;
   --  Length of a SHA-256/224 block in bytes

   SHA224_Hash_Length : constant Hash_Length_Number := 28;
   SHA256_Hash_Length : constant Hash_Length_Number := 32;

   Hash_Length : constant array (Algorithm_Kind) of Hash_Length_Number :=
     (SHA224 => SHA224_Hash_Length,
      SHA256 => SHA256_Hash_Length);

   subtype SHA224_Hash is Byte_Array (1 .. SHA224_Hash_Length);
   subtype SHA256_Hash is Byte_Array (1 .. SHA256_Hash_Length);

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited private;

   function Finished (Ctx : Context) return Boolean with
     Global => null;

   procedure Initialize (Ctx : out Context) with
     Global => null,
     Post   => not Finished (Ctx);

   procedure Sanitize (Ctx : out Context) with
     Global  => null,
     Post => Finished (Ctx);

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Global     => null,
     Pre  => not Finished (Ctx),
     Post => not Finished (Ctx);

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Byte_Array)
   with
     Relaxed_Initialization => Hash,
     Global => null,
     Pre    => not Finished (Ctx) and
               Hash'Length = Hash_Length (Ctx.Algorithm),
     Post   => Finished (Ctx) and Hash'Initialized;

   ----------------------------
   -- Single-Part Operations --
   ----------------------------

   procedure Compute_Hash
     (Algorithm :     Algorithm_Kind;
      Data      :     Byte_Array;
      Hash      : out Byte_Array)
   with
     Pre => Hash'Length = Hash_Length (Algorithm);

   function Verify_Hash
     (Algorithm     : Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   with
     Pre => Expected_Hash'Length in 1 .. Hash_Length (Algorithm);

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
