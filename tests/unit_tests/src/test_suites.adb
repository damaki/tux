--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Conversions_Tests;
with SHA1_Self_Tests;
with SHA256_Self_Tests;
with SHA512_Self_Tests;
with SHA512_Length_Tests;
with Hashing_Tests;
with HMAC_Tests;
with HKDF_Tests;

package body Test_Suites
is
   function Suite return Access_Test_Suite
   is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      S.Add_Test (Conversions_Tests.Suite);
      S.Add_Test (SHA1_Self_Tests.Suite);
      S.Add_Test (SHA256_Self_Tests.Suite);
      S.Add_Test (SHA512_Self_Tests.Suite);
      S.Add_Test (Hashing_Tests.Suite);
      S.Add_Test (SHA512_Length_Tests.Suite);
      S.Add_Test (HMAC_Tests.Suite);
      S.Add_Test (HKDF_Tests.Suite);

      return S;
   end Suite;

end Test_Suites;