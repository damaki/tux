--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types; use Tux.Types;

--  This stub implementation is used when SHA-1 is disabled in the crate
--  configuration. The purpose of this stub is to allow compilation against
--  this package so that facilities such as Tux.Hashing will still compile.

--  @private
package Tux.SHA1 with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode
is

   Block_Length : constant Byte_Count := 64;
   --  Length of a SHA-1 block in bytes

   SHA1_Hash_Length : constant Byte_Count := 20;

   subtype SHA1_Hash is Byte_Array (1 .. SHA1_Hash_Length);

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context is limited private;

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
     (Data :     Byte_Array;
      Hash : out Byte_Array)
   with
     Inline,
     Pre => False;

   function Verify_Hash
     (Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   with
     Inline,
     Pre => False;

private

   type Context is limited null record;

end Tux.SHA1;
