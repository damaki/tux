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

package Hashing_Tests is

   generic
      Algorithm : Tux.Hashing.Algorithm_Kind;

   package Generic_Hashing_Tests is

      type Test is new AUnit.Test_Fixtures.Test_Fixture with record
         Buffer : Tux.Types.Byte_Array (1 .. 16_384);
      end record;

      overriding
      procedure Set_Up (T : in out Test);

      ------------------------------
      -- Multi-Part Message Tests --
      ------------------------------

      --  These tests verify that a multi-part hashing operation with varying
      --  part sizes produces the same result as the equivalent single-part
      --  operation.

      procedure Test_Multi_Part_1 (T : in out Test);
      procedure Test_Multi_Part_2 (T : in out Test);
      procedure Test_Multi_Part_31 (T : in out Test);
      procedure Test_Multi_Part_32 (T : in out Test);
      procedure Test_Multi_Part_33 (T : in out Test);
      procedure Test_Multi_Part_63 (T : in out Test);
      procedure Test_Multi_Part_64 (T : in out Test);
      procedure Test_Multi_Part_65 (T : in out Test);
      procedure Test_Multi_Part_127 (T : in out Test);
      procedure Test_Multi_Part_128 (T : in out Test);
      procedure Test_Multi_Part_129 (T : in out Test);

      -----------------------
      -- Hash Verify Tests --
      -----------------------

      procedure Test_Verify_Valid_Hash (T : in out Test);
      procedure Test_Verify_Invalid_First_Byte (T : in out Test);
      procedure Test_Verify_Invalid_Last_Byte (T : in out Test);

      procedure Test_Finish_Verify_Valid_Hash (T : in out Test);
      procedure Test_Finish_Verify_Invalid_First_Byte (T : in out Test);
      procedure Test_Finish_Verify_Invalid_Last_Byte (T : in out Test);

      procedure Add_To_Suite (S : in out Test_Suite'Class);

   private

      package Caller is new AUnit.Test_Caller (Test);

   end Generic_Hashing_Tests;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite;

private

   procedure Multi_Part_Test
     (Buffer      : Tux.Types.Byte_Array;
      Algorithm   : Tux.Hashing.Algorithm_Kind;
      Part_Length : Positive)
   with
     Pre => Part_Length <= Buffer'Length;
   --  Test that a multi-part hashing operation with blocks of size Part_Length
   --  produces the same result as the equivalent single-part operation.

end Hashing_Tests;
