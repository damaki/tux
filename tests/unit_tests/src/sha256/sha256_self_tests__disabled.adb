--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This is the stub implementation of these tests for when either
--  SHA-256 or the self-tests are disabled.

package body SHA256_Self_Tests is

   ----------------------------
   -- Test_SHA256_Self_Tests --
   ----------------------------

   procedure Test_SHA256_Self_Tests (T : in out Test) is null;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
   begin
      return new Test_Suite;
   end Suite;

end SHA256_Self_Tests;