--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;

with Interfaces; use Interfaces;

with Tux.Types;             use Tux.Types;
with Tux.Types.Conversions; use Tux.Types.Conversions;

package body Conversions_Tests is

   --------------------------
   -- Test_To_Bytes_LE_U32 --
   --------------------------

   procedure Test_To_Bytes_LE_U32 (T : in out Test) is
      Bytes : Byte_Array (1 .. 4);
   begin
      To_Bytes_LE (Unsigned_32 (16#00112233#), Bytes);
      Assert (Bytes = (16#33#, 16#22#, 16#11#, 16#00#),
              "Incorrect conversion");
   end Test_To_Bytes_LE_U32;

   --------------------------
   -- Test_To_Bytes_LE_U64 --
   --------------------------

   procedure Test_To_Bytes_LE_U64 (T : in out Test) is
      Bytes : Byte_Array (1 .. 8);
   begin
      To_Bytes_LE (Unsigned_64 (16#00112233_44556677#), Bytes);
      Assert (Bytes = (16#77#, 16#66#, 16#55#, 16#44#,
                       16#33#, 16#22#, 16#11#, 16#00#),
              "Incorrect conversion");
   end Test_To_Bytes_LE_U64;

   --------------------------
   -- Test_To_Bytes_BE_U32 --
   --------------------------

   procedure Test_To_Bytes_BE_U32 (T : in out Test) is
      Bytes : Byte_Array (1 .. 4);
   begin
      To_Bytes_BE (Unsigned_32 (16#00112233#), Bytes);
      Assert (Bytes = (16#00#, 16#11#, 16#22#, 16#33#),
              "Incorrect conversion");
   end Test_To_Bytes_BE_U32;

   --------------------------
   -- Test_To_Bytes_BE_U64 --
   --------------------------

   procedure Test_To_Bytes_BE_U64 (T : in out Test) is
      Bytes : Byte_Array (1 .. 8);
   begin
      To_Bytes_BE (Unsigned_64 (16#00112233_44556677#), Bytes);
      Assert (Bytes = (16#00#, 16#11#, 16#22#, 16#33#,
                       16#44#, 16#55#, 16#66#, 16#77#),
              "Incorrect conversion");
   end Test_To_Bytes_BE_U64;

   --------------------
   -- Test_To_U32_LE --
   --------------------

   procedure Test_To_U32_LE (T : in out Test) is
      Value : Unsigned_32;
   begin
      Value := To_U32_LE (Byte_Array'(16#00#, 16#11#, 16#22#, 16#33#));
      Assert (Value = 16#33221100#, "Incorrect conversion");
   end Test_To_U32_LE;

   --------------------
   -- Test_To_U64_LE --
   --------------------

   procedure Test_To_U64_LE (T : in out Test) is
      Value : Unsigned_64;
   begin
      Value := To_U64_LE (Byte_Array'(16#00#, 16#11#, 16#22#, 16#33#,
                                      16#44#, 16#55#, 16#66#, 16#77#));
      Assert (Value = 16#77665544_33221100#, "Incorrect conversion");
   end Test_To_U64_LE;

   --------------------
   -- Test_To_U32_BE --
   --------------------

   procedure Test_To_U32_BE (T : in out Test) is
      Value : Unsigned_32;
   begin
      Value := To_U32_BE (Byte_Array'(16#00#, 16#11#, 16#22#, 16#33#));
      Assert (Value = 16#00112233#, "Incorrect conversion");
   end Test_To_U32_BE;

   --------------------
   -- Test_To_U64_BE --
   --------------------

   procedure Test_To_U64_BE (T : in out Test) is
      Value : Unsigned_64;
   begin
      Value := To_U64_BE (Byte_Array'(16#00#, 16#11#, 16#22#, 16#33#,
                                      16#44#, 16#55#, 16#66#, 16#77#));
      Assert (Value = 16#00112233_44556677#, "Incorrect conversion");
   end Test_To_U64_BE;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      S.Add_Test (Caller.Create ("Test To_Bytes_LE_U32",
                                 Test_To_Bytes_LE_U32'Access));
      S.Add_Test (Caller.Create ("Test To_Bytes_LE_U64",
                                 Test_To_Bytes_LE_U64'Access));
      S.Add_Test (Caller.Create ("Test To_Bytes_BE_U32",
                                 Test_To_Bytes_BE_U32'Access));
      S.Add_Test (Caller.Create ("Test To_Bytes_BE_U64",
                                 Test_To_Bytes_BE_U64'Access));
      S.Add_Test (Caller.Create ("Test To_U32_LE",
                                 Test_To_U32_LE'Access));
      S.Add_Test (Caller.Create ("Test To_U64_LE",
                                 Test_To_U64_LE'Access));
      S.Add_Test (Caller.Create ("Test To_U32_BE",
                                 Test_To_U32_BE'Access));
      S.Add_Test (Caller.Create ("Test To_U64_BE",
                                 Test_To_U64_BE'Access));
      return S;
   end Suite;

end Conversions_Tests;
