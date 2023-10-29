--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types; use Tux.Types;

--  This stub implementation is used when SHAKE is disabled in the crate
--  configuration. The purpose of this stub is to allow compilation against
--  this package so that facilities such as Tux.XOF will still compile.

package Tux.SHAKE with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   type Algorithm_Kind is (SHAKE128, SHAKE256);

   SHAKE128_Block_Length : constant Byte_Count := (1600 - (128 * 2)) / 8;
   SHAKE256_Block_Length : constant Byte_Count := (1600 - (256 * 2)) / 8;

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type State_Kind is (Updating, Extracting);

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited private;

   function Current_State (Ctx : Context) return State_Kind;

   procedure Initialize (Ctx : out Context) with
     Inline,
     Pre => False;

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Inline,
     Pre => False;

   procedure Extract
     (Ctx    : in out Context;
      Output :    out Byte_Array)
   with
     Inline,
     Pre => False;

   procedure Sanitize (Ctx : out Context) with
     Inline,
     Pre => False;

private

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited null record;

end Tux.SHAKE;