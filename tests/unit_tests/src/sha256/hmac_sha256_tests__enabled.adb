--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with HMAC_Tests;

with Tux.Hashing;

package body HMAC_SHA256_Tests is

   package Tests_224 is new HMAC_Tests.Generic_HMAC_Tests (Tux.Hashing.SHA224);
   package Tests_256 is new HMAC_Tests.Generic_HMAC_Tests (Tux.Hashing.SHA256);

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      Tests_224.Add_To_Suite (S.all);
      Tests_256.Add_To_Suite (S.all);
      return S;
   end Suite;

end HMAC_SHA256_Tests;