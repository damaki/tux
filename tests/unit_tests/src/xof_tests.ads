--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

with AUnit.Test_Fixtures;
with AUnit.Test_Suites;   use AUnit.Test_Suites;
with AUnit.Test_Caller;

with Tux.Types;
with Tux.XOF;

package XOF_Tests is

   generic
      Algorithm : Tux.XOF.Algorithm_Kind;

   package Generic_XOF_Tests is

      type Test is new AUnit.Test_Fixtures.Test_Fixture with record
         Buffer : Tux.Types.Byte_Array (1 .. 16_384);
      end record;

      overriding
      procedure Set_Up (T : in out Test);

      procedure Test_Multi_Part_Input (T : in out Test);
      procedure Test_Multi_Part_Output (T : in out Test);
      procedure Test_Verify_Valid_Hash (T : in out Test);
      procedure Test_Verify_Invalid_Hash (T : in out Test);
      procedure Test_Finish_Verify_Valid_Hash (T : in out Test);
      procedure Test_Finish_Verify_Invalid_Hash (T : in out Test);

      procedure Add_To_Suite (S : in out Test_Suite'Class);

   private

      package Caller is new AUnit.Test_Caller (Test);

   end Generic_XOF_Tests;

private

   procedure Multi_Part_Input_Test
     (Buffer      : Tux.Types.Byte_Array;
      Algorithm   : Tux.XOF.Algorithm_Kind;
      Part_Length : Positive)
   with
     Pre => Part_Length <= Buffer'Length;
   --  Test that a multi-part hashing operation with blocks of size Part_Length
   --  produces the same result as the equivalent single-part operation.

   procedure Multi_Part_Output_Test
     (Hash           : in out Tux.Types.Byte_Array;
      Reference_Hash : in out Tux.Types.Byte_Array;
      Algorithm      :        Tux.XOF.Algorithm_Kind;
      Part_Length    :        Positive)
   with
     Pre => (Part_Length <= Hash'Length
             and then Hash'Length = Reference_Hash'Length);
   --  Test that extracting the output in multiple parts with blocks of size
   --  Part_Length produces the same result as the equivalent single-part
   --  operation.

end XOF_Tests;
