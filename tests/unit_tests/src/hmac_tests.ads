--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Test_Fixtures;
with AUnit.Test_Suites;   use AUnit.Test_Suites;
with AUnit.Test_Caller;

with Tux.Types;
with Tux.Hashing;

package HMAC_Tests is

   generic
      Algorithm : Tux.Hashing.Algorithm_Kind;
   package Generic_HMAC_Tests is

      type Test is new AUnit.Test_Fixtures.Test_Fixture with record
         Buffer : Tux.Types.Byte_Array (1 .. 16_384);
      end record;

      overriding
      procedure Set_Up (T : in out Test);

      procedure Test_Multi_Part (T : in out Test);
      procedure Test_Verify_Valid_HMAC (T : in out Test);
      procedure Test_Verify_Invalid_HMAC (T : in out Test);
      procedure Test_Finish_And_Verify_Valid_HMAC (T : in out Test);
      procedure Test_Finish_And_Verify_Invalid_HMAC (T : in out Test);

      procedure Add_To_Suite (S : in out Test_Suite'Class);

   private

      package Caller is new AUnit.Test_Caller (Test);

   end Generic_HMAC_Tests;

private

   procedure Multi_Part_Test
     (Buffer      : Tux.Types.Byte_Array;
      Algorithm   : Tux.Hashing.Algorithm_Kind;
      Part_Length : Positive)
   with
     Pre => Part_Length <= Buffer'Length;

end HMAC_Tests;
