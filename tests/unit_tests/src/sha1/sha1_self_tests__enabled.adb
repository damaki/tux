--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;
with Tux.SHA1.Self_Test;

package body SHA1_Self_Tests is

   --------------------------
   -- Test_SHA1_Self_Tests --
   --------------------------

   procedure Test_SHA1_Self_Tests (T : in out Test) is
   begin
      Assert (Tux.SHA1.Self_Test, "Unexpected failure");
   end Test_SHA1_Self_Tests;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      S.Add_Test
        (Caller.Create
           ("SHA-1 Self Test with correct implementation",
            Test_SHA1_Self_Tests'Access));
      return S;
   end Suite;

end SHA1_Self_Tests;