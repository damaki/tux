--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.SHA3 with
  SPARK_Mode
is

   --------------
   -- Finished --
   --------------

   function Finished (Ctx : Context) return Boolean is
      pragma Unreferenced (Ctx);
   begin
      return False;
   end Finished;

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
      pragma Unreferenced (Ctx);
   begin
      null;
   end Initialize;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
      pragma Unreferenced (Ctx);
   begin
      null;
   end Sanitize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
      pragma Unreferenced (Ctx);
      pragma Unreferenced (Data);
   begin
      null;
   end Update;

   ------------
   -- Finish --
   ------------

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Byte_Array)
   is
      pragma Unreferenced (Ctx);
   begin
      Hash := (others => 0);
   end Finish;

   ------------------
   -- Compute_Hash --
   ------------------

   procedure Compute_Hash
     (Algorithm :     Algorithm_Kind;
      Data      :     Byte_Array;
      Hash      : out Byte_Array)
   is
      pragma Unreferenced (Algorithm);
      pragma Unreferenced (Data);
   begin
      Hash := (others => 0);
   end Compute_Hash;

   -----------------
   -- Verify_Hash --
   -----------------

   function Verify_Hash
     (Algorithm     : Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   is
      pragma Unreferenced (Algorithm);
      pragma Unreferenced (Data);
      pragma Unreferenced (Expected_Hash);
   begin
      return False;
   end Verify_Hash;

end Tux.SHA3;
