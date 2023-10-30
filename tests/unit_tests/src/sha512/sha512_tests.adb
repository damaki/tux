--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Hashing_Tests;

with Tux_Config;
with Tux.Hashing;

package body SHA512_Tests is

   package Tests_384 is new
     Hashing_Tests.Generic_Hashing_Tests (Tux.Hashing.SHA384);

   package Tests_512 is new
     Hashing_Tests.Generic_Hashing_Tests (Tux.Hashing.SHA512);

   package Tests_512_224 is new
     Hashing_Tests.Generic_Hashing_Tests (Tux.Hashing.SHA512_224);

   package Tests_512_256 is new
     Hashing_Tests.Generic_Hashing_Tests (Tux.Hashing.SHA512_256);

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      if Tux_Config.SHA512_Enabled then
         Tests_384.Add_To_Suite (S.all);
         Tests_512.Add_To_Suite (S.all);
         Tests_512_224.Add_To_Suite (S.all);
         Tests_512_256.Add_To_Suite (S.all);
      end if;

      return S;
   end Suite;

end SHA512_Tests;