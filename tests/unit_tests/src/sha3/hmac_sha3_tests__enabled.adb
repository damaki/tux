--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with HMAC_Tests;

with Tux.Hashing;

package body HMAC_SHA3_Tests is

   package Tests_224 is new HMAC_Tests.Generic_HMAC_Tests
     (Tux.Hashing.SHA3_224);

   package Tests_256 is new HMAC_Tests.Generic_HMAC_Tests
     (Tux.Hashing.SHA3_256);

   package Tests_384 is new HMAC_Tests.Generic_HMAC_Tests
     (Tux.Hashing.SHA3_384);

   package Tests_512 is new HMAC_Tests.Generic_HMAC_Tests
     (Tux.Hashing.SHA3_512);

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      Tests_224.Add_To_Suite (S.all);
      Tests_256.Add_To_Suite (S.all);
      Tests_384.Add_To_Suite (S.all);
      Tests_512.Add_To_Suite (S.all);
      return S;
   end Suite;

end HMAC_SHA3_Tests;