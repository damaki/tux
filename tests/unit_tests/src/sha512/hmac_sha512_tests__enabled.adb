--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with HMAC_Tests;

with Tux.Hashing;

package body HMAC_SHA512_Tests is

   package Tests_384 is new
     HMAC_Tests.Generic_HMAC_Tests (Tux.Hashing.SHA384);

   package Tests_512 is new
     HMAC_Tests.Generic_HMAC_Tests (Tux.Hashing.SHA512);

   package Tests_512_224 is new
     HMAC_Tests.Generic_HMAC_Tests (Tux.Hashing.SHA512_224);

   package Tests_512_256 is new
     HMAC_Tests.Generic_HMAC_Tests (Tux.Hashing.SHA512_256);

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      Tests_384.Add_To_Suite (S.all);
      Tests_512.Add_To_Suite (S.all);
      Tests_512_224.Add_To_Suite (S.all);
      Tests_512_256.Add_To_Suite (S.all);
      return S;
   end Suite;

end HMAC_SHA512_Tests;