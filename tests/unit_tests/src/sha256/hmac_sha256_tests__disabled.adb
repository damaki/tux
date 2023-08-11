--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This is the stub implementation of these tests for when SHA-256 is
--  disabled in the library configuration.

package body HMAC_SHA256_Tests is

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
   begin
      return new Test_Suite;
   end Suite;

end HMAC_SHA256_Tests;