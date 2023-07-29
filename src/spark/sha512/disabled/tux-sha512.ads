--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types; use Tux.Types;

--  This stub implementation is used when SHA-512 is disabled in the crate
--  configuration. The purpose of this stub is to allow compilation against
--  this package so that facilities such as Tux.Hashing will still compile.

--  @private
package Tux.SHA512 with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode
is

   type Algorithm_Kind is (SHA384, SHA512, SHA512_224, SHA512_256);

   subtype Hash_Length_Number is Byte_Count range 28 .. 64;

   Block_Length : constant Byte_Count := 128;

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
     Inline,
     Global => null,
     Pre    => False;

   procedure Initialize (Ctx  : out Context) with
     Inline,
     Global => null,
     Pre    => False;

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Inline,
     Global => null,
     Pre    => False;

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Byte_Array)
   with
     Inline,
     Global => null,
     Pre    => False;

   procedure Sanitize (Ctx : out Context) with
     Inline,
     Global => null,
     Pre    => False;

   ----------------------------
   -- Single-Part Operations --
   ----------------------------

   procedure Compute_Hash
     (Algorithm :     Algorithm_Kind;
      Data      :     Byte_Array;
      Hash      : out Byte_Array)
   with
     Inline,
     Global => null,
     Pre    => False;

   function Verify_Hash
     (Algorithm     : Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   with
     Inline,
     Global => null,
     Pre    => False;

private

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited null record;

end Tux.SHA512;
