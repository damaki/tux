--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;
with Tux.Types;
with Tux.SHA512;
with Tux.SHA512.Test_Access;
with Interfaces; use Interfaces;

package body SHA512_Length_Tests is

   ----------------------------------------
   -- Test_SHA512_64bit_Length_Increment --
   ----------------------------------------

   --  Test that the 128-bit message length correctly increments when the
   --  message length exceeds 2**64 bytes.

   procedure Test_SHA512_64bit_Length_Increment (T : in out Test) is

      Bytes_5 : constant Tux.Types.Byte_Array (1 .. 5) := (others => 0);

      Ctx : Tux.SHA512.Context (Tux.SHA512.SHA512);

   begin
      Tux.SHA512.Initialize (Ctx);

      Tux.SHA512.Test_Access.Set_Byte_Length
        (Ctx  => Ctx,
         Low  => Unsigned_64'Last - 1,
         High => 0);

      Tux.SHA512.Update (Ctx, Bytes_5);

      Assert (Tux.SHA512.Test_Access.Get_Byte_Length_Low (Ctx) = 3,
              "wrong low word");

      Assert (Tux.SHA512.Test_Access.Get_Byte_Length_High (Ctx) = 1,
              "wrong high word");
   end Test_SHA512_64bit_Length_Increment;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      S.Add_Test
        (Caller.Create
           ("SHA-512 test 64-bit length rollover",
            Test_SHA512_64bit_Length_Increment'Access));
      return S;
   end Suite;

end SHA512_Length_Tests;