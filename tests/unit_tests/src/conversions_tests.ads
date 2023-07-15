--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Test_Fixtures;
with AUnit.Test_Suites;   use AUnit.Test_Suites;
with AUnit.Test_Caller;

package Conversions_Tests is

   type Test is new AUnit.Test_Fixtures.Test_Fixture with null record;

   procedure Test_To_Bytes_LE_U32 (T : in out Test);
   procedure Test_To_Bytes_LE_U64 (T : in out Test);
   procedure Test_To_Bytes_BE_U32 (T : in out Test);
   procedure Test_To_Bytes_BE_U64 (T : in out Test);

   procedure Test_To_U32_LE (T : in out Test);
   procedure Test_To_U64_LE (T : in out Test);
   procedure Test_To_U32_BE (T : in out Test);
   procedure Test_To_U64_BE (T : in out Test);

   function Suite return Access_Test_Suite;

private

   package Caller is new AUnit.Test_Caller (Test);

end Conversions_Tests;