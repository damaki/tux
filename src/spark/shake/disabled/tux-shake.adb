--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.SHAKE with
  SPARK_Mode
is

   -------------------
   -- Current_State --
   -------------------

   function Current_State (Ctx : Context) return State_Kind is
      pragma Unreferenced (Ctx);
   begin
      return State_Kind'First;
   end Current_State;

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
      pragma Unreferenced (Ctx);
   begin
      null;
   end Initialize;

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

   -------------
   -- Extract --
   -------------

   procedure Extract
     (Ctx    : in out Context;
      Output :    out Byte_Array)
   is
      pragma Unreferenced (Ctx);
   begin
      Output := (others => 0);
   end Extract;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
      pragma Unreferenced (Ctx);
   begin
      null;
   end Sanitize;

end Tux.SHAKE;