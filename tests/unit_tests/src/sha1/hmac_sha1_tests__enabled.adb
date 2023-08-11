--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with HMAC_Tests;

with Tux.Hashing;

package body HMAC_SHA1_Tests is

   package Tests is new HMAC_Tests.Generic_HMAC_Tests (Tux.Hashing.SHA1);

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      Tests.Add_To_Suite (S.all);
      return S;
   end Suite;

end HMAC_SHA1_Tests;