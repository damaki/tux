--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Test_Fixtures;
with AUnit.Test_Suites;   use AUnit.Test_Suites;
with AUnit.Test_Caller;

package HKDF_Tests is

   type Test is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure Test_Empty_OKM (T : in out Test);

   function Suite return Access_Test_Suite;

private

   package Caller is new AUnit.Test_Caller (Test);

end HKDF_Tests;