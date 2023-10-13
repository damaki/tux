--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This is the stub implementation of these tests for when SHA-512 is
--  disabled in the library configuration.

package body SHA512_Length_Tests is

   procedure Test_SHA512_64bit_Length_Increment (T : in out Test) is null;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
   begin
      return new Test_Suite;
   end Suite;

end SHA512_Length_Tests;