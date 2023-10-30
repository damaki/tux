--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Hashing_Tests;

with Tux.Hashing;

package body SHA256_Tests is

   package Tests_224 is new
      Hashing_Tests.Generic_Hashing_Tests (Tux.Hashing.SHA224);

   package Tests_256 is new
      Hashing_Tests.Generic_Hashing_Tests (Tux.Hashing.SHA256);

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      if Tux_Config.SHA256_Enabled then
         Tests_224.Add_To_Suite (S.all);
         Tests_256.Add_To_Suite (S.all);
      end if;

      return S;
   end Suite;

end SHA256_Tests;