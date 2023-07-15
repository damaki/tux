--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Test_Fixtures;
with AUnit.Test_Suites;   use AUnit.Test_Suites;
with AUnit.Test_Caller;

package SHA256_Self_Tests is

   type Test is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure Test_SHA256_Self_Tests (T : in out Test);

   function Suite return Access_Test_Suite;

private

   package Caller is new AUnit.Test_Caller (Test);

end SHA256_Self_Tests;