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
package Tux.SHA512 with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   type Algorithm_Kind is (SHA384, SHA512, SHA512_224, SHA512_256);

   subtype Hash_Length_Number is Byte_Count range 28 .. 64;

   Block_Length : constant Byte_Count := 128;
   --  Length of a SHA-512 block in bytes

   SHA512_224_Hash_Length : constant Hash_Length_Number := 28;
   SHA512_256_Hash_Length : constant Hash_Length_Number := 32;
   SHA384_Hash_Length     : constant Hash_Length_Number := 48;
   SHA512_Hash_Length     : constant Hash_Length_Number := 64;

   Hash_Length : constant array (Algorithm_Kind) of Hash_Length_Number :=
     (SHA384     => SHA384_Hash_Length,
      SHA512     => SHA512_Hash_Length,
      SHA512_224 => SHA512_224_Hash_Length,
      SHA512_256 => SHA512_256_Hash_Length);

   subtype SHA384_Hash is Byte_Array (1 .. SHA384_Hash_Length);
   subtype SHA512_Hash is Byte_Array (1 .. SHA512_Hash_Length);
   subtype SHA512_224_Hash is Byte_Array (1 .. SHA512_224_Hash_Length);
   subtype SHA512_256_Hash is Byte_Array (1 .. SHA512_256_Hash_Length);

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited private;

   function Finished (Ctx : Context) return Boolean with
     Global => null;

   procedure Initialize (Ctx  : out Context) with
     Global => null,
     Post   => not Finished (Ctx);

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Global => null,
     Pre    => not Finished (Ctx),
     Post   => not Finished (Ctx);

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Byte_Array)
   with
     Relaxed_Initialization => Hash,
     Global  => null,
     Pre     => not Finished (Ctx) and
                Hash'Length = Hash_Length (Ctx.Algorithm),
     Post    => Finished (Ctx) and Hash'Initialized;

   procedure Sanitize (Ctx : out Context) with
     Global  => null,
     Post   => Finished (Ctx);

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
