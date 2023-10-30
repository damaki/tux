--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;

with Tux_Config;
with Tux.SHA256.Self_Test;

package body SHA256_Self_Tests is

   ----------------------------
   -- Test_SHA256_Self_Tests --
   ----------------------------

   procedure Test_SHA256_Self_Tests (T : in out Test) is
   begin
      Assert (Tux.SHA256.Self_Test, "Unexpected failure");
   end Test_SHA256_Self_Tests;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      if Tux_Config.SHA256_Enabled then
         S.Add_Test
           (Caller.Create
              ("SHA-256 Self Test with correct implementation",
               Test_SHA256_Self_Tests'Access));
      end if;

      return S;
   end Suite;

end SHA256_Self_Tests;