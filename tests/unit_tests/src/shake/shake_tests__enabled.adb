--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with XOF_Tests;

with Tux.XOF;

package body SHAKE_Tests is

   package Tests_128 is new
      XOF_Tests.Generic_XOF_Tests (Tux.XOF.SHAKE128);

   package Tests_256 is new
      XOF_Tests.Generic_XOF_Tests (Tux.XOF.SHAKE256);

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      Tests_128.Add_To_Suite (S.all);
      Tests_256.Add_To_Suite (S.all);
      return S;
   end Suite;

end SHAKE_Tests;