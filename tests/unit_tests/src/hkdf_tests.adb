--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Hashing;
with Tux.HKDF;
with Tux.Types;

package body HKDF_Tests is

   ----------------------------
   -- Test_Empty_OKM --
   ----------------------------

   procedure Test_Empty_OKM (T : in out Test) is
      OKM : Tux.Types.Byte_Array (1 .. 0);
   begin
      Tux.HKDF.HKDF
        (Algorithm => Tux.Hashing.SHA256,
         Salt      => Tux.Types.Empty_Byte_Array,
         IKM       => Tux.Types.Empty_Byte_Array,
         Info      => Tux.Types.Empty_Byte_Array,
         OKM       => OKM);
   end Test_Empty_OKM;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin
      S.Add_Test
        (Caller.Create
           ("HKDF test empty OKM",
            Test_Empty_OKM'Access));
      return S;
   end Suite;

end HKDF_Tests;