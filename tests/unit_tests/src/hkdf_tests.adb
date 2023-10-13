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
      --  Run the test on the first algorithm that is enabled in the test
      --  configuration.

      for Algo in Tux.Hashing.Algorithm_Kind loop
         if Algo in Tux.Hashing.Enabled_Algorithm_Kind then
            Tux.HKDF.HKDF
              (Algorithm => Algo,
               Salt      => Tux.Types.Empty_Byte_Array,
               IKM       => Tux.Types.Empty_Byte_Array,
               Info      => Tux.Types.Empty_Byte_Array,
               OKM       => OKM);
            exit;
         end if;
      end loop;
   end Test_Empty_OKM;

   -----------
   -- Suite --
   -----------

   function Suite return Access_Test_Suite is
      --  All hash algorithms might be disabled in some test configurations

      Has_Enabled_Hash_Algo : constant Boolean :=
        (for some A in Tux.Hashing.Algorithm_Kind =>
           A in Tux.Hashing.Enabled_Algorithm_Kind);

      S : constant Access_Test_Suite := new Test_Suite;
   begin
      --  HKDF relies on a hash algorithm, so skip these tests if all hash
      --  algorithms are disabled.

      if Has_Enabled_Hash_Algo then
         S.Add_Test
         (Caller.Create
            ("HKDF test empty OKM",
               Test_Empty_OKM'Access));
      end if;

      return S;
   end Suite;

end HKDF_Tests;