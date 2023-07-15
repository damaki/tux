--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.SHA512.Test_Access with
  Preelaborate
is

   procedure Set_Byte_Length
     (Ctx  : in out Context;
      Low  :        Unsigned_64;
      High :        Unsigned_64)
   is
   begin
      Ctx.Byte_Length_Low  := Low;
      Ctx.Byte_Length_High := High;
   end Set_Byte_Length;

   function Get_Byte_Length_Low  (Ctx : Context) return Unsigned_64 is
     (Ctx.Byte_Length_Low);

   function Get_Byte_Length_High (Ctx : Context) return Unsigned_64 is
     (Ctx.Byte_Length_High);

end Tux.SHA512.Test_Access;