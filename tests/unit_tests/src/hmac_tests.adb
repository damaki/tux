--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;
with Interfaces;       use Interfaces;

with Tux.HMAC;

package body HMAC_Tests is

   ------------------------------
   -- Multi-Part Message Tests --
   ------------------------------

   procedure Multi_Part_Test
     (Buffer      : Tux.Types.Byte_Array;
      Algorithm   : Tux.Hashing.Algorithm_Kind;
      Part_Length : Positive)
   is
      use type Tux.Types.Byte_Array;

      MAC_Len : constant Tux.HMAC.HMAC_Length_Number :=
                  Tux.HMAC.HMAC_Length (Algorithm);

      MAC           : Tux.Types.Byte_Array (1 .. MAC_Len);
      Reference_MAC : Tux.Types.Byte_Array (1 .. MAC_Len);

      Key : constant Tux.Types.Byte_Array (1 .. 16) := (others => 16#AA#);

      Ctx : Tux.HMAC.Context (Algorithm);

      Offset    : Natural := 0;
      Remaining : Natural := Buffer'Length;
      Pos       : Tux.Types.Index_Number;

   begin
      Tux.HMAC.Compute_HMAC
        (Algorithm => Algorithm,
         Key       => Key,
         Data      => Buffer,
         MAC       => Reference_MAC);

      Tux.HMAC.Initialize (Ctx, Key);

      while Remaining >= Part_Length loop
         Pos := Buffer'First + Offset;

         Tux.HMAC.Update (Ctx, Buffer (Pos .. Pos + Part_Length - 1));

         Offset    := Offset    + Part_Length;
         Remaining := Remaining - Part_Length;
      end loop;

      Tux.HMAC.Update (Ctx, Buffer (Buffer'First + Offset .. Buffer'Last));
      Tux.HMAC.Finish (Ctx, MAC);

      Assert (Tux.HMAC.Finished (Ctx), "HMAC context not finished");

      Assert (MAC = Reference_MAC,
              "Multi-part MAC does not match single-part MAC");
   end Multi_Part_Test;

   package body Generic_HMAC_Tests is

      ------------
      -- Set_Up --
      ------------

      overriding
      procedure Set_Up (T : in out Test) is
      begin
         for I in T.Buffer'Range loop
            T.Buffer (I) := Unsigned_8 (I mod 256);
         end loop;
      end Set_Up;

      procedure Test_Multi_Part_1 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 1);
      end Test_Multi_Part_1;

      procedure Test_Multi_Part_2 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 2);
      end Test_Multi_Part_2;

      procedure Test_Multi_Part_31 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 31);
      end Test_Multi_Part_31;

      procedure Test_Multi_Part_32 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 32);
      end Test_Multi_Part_32;

      procedure Test_Multi_Part_33 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 33);
      end Test_Multi_Part_33;

      procedure Test_Multi_Part_63 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 63);
      end Test_Multi_Part_63;

      procedure Test_Multi_Part_64 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 64);
      end Test_Multi_Part_64;

      procedure Test_Multi_Part_65 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 65);
      end Test_Multi_Part_65;

      procedure Test_Multi_Part_127 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 127);
      end Test_Multi_Part_127;

      procedure Test_Multi_Part_128 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 128);
      end Test_Multi_Part_128;

      procedure Test_Multi_Part_129 (T : in out Test) is
      begin
         Multi_Part_Test (T.Buffer, Algorithm, 129);
      end Test_Multi_Part_129;

      ----------------------------
      -- Test_Verify_Valid_HMAC --
      ----------------------------

      procedure Test_Verify_Valid_HMAC (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key   : constant Tux.Types.Byte_Array (1 .. HLen) := (others => 0);
         HMAC  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => HMAC);

         Valid := Tux.HMAC.Verify_HMAC
                    (Algorithm    => Algorithm,
                     Key          => Key,
                     Data         => T.Buffer,
                     Expected_MAC => HMAC);

         Assert (Valid, "HMAC verify failed");
      end Test_Verify_Valid_HMAC;

      ------------------------------------
      -- Test_Verify_Invalid_First_Byte --
      ------------------------------------

      procedure Test_Verify_Invalid_First_Byte (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key   : constant Tux.Types.Byte_Array (1 .. HLen) := (others => 0);
         HMAC  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => HMAC);

         --  Corrupt a bit in the first byte
         HMAC (HMAC'First) := HMAC (HMAC'First) xor 1;

         Valid := Tux.HMAC.Verify_HMAC
                    (Algorithm    => Algorithm,
                     Key          => Key,
                     Data         => T.Buffer,
                     Expected_MAC => HMAC);

         Assert (not Valid, "Invalid HMAC not detected");
      end Test_Verify_Invalid_First_Byte;

      -----------------------------------
      -- Test_Verify_Invalid_Last_Byte --
      -----------------------------------

      procedure Test_Verify_Invalid_Last_Byte (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key   : constant Tux.Types.Byte_Array (1 .. HLen) := (others => 0);
         HMAC  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => HMAC);

         --  Corrupt a bit in the last byte
         HMAC (HMAC'Last) := HMAC (HMAC'Last) xor 2#1000_0000#;

         Valid := Tux.HMAC.Verify_HMAC
                    (Algorithm    => Algorithm,
                     Key          => Key,
                     Data         => T.Buffer,
                     Expected_MAC => HMAC);

         Assert (not Valid, "Invalid HMAC not detected");
      end Test_Verify_Invalid_Last_Byte;

      ----------------------------
      -- Test_Finish_And_Verify_Valid_HMAC --
      ----------------------------

      procedure Test_Finish_And_Verify_Valid_HMAC (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key   : constant Tux.Types.Byte_Array (1 .. HLen) := (others => 0);
         HMAC  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.HMAC.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => HMAC);

         Tux.HMAC.Initialize (Ctx, Key);
         Tux.HMAC.Update (Ctx, T.Buffer);
         Tux.HMAC.Finish_And_Verify (Ctx, HMAC, Valid);

         Assert (Valid, "HMAC verify failed");
      end Test_Finish_And_Verify_Valid_HMAC;

      ------------------------------------
      -- Test_Finish_And_Verify_Invalid_First_Byte --
      ------------------------------------

      procedure Test_Finish_And_Verify_Invalid_First_Byte (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key   : constant Tux.Types.Byte_Array (1 .. HLen) := (others => 0);
         HMAC  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.HMAC.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => HMAC);

         --  Corrupt a bit in the first byte
         HMAC (HMAC'First) := HMAC (HMAC'First) xor 1;

         Tux.HMAC.Initialize (Ctx, Key);
         Tux.HMAC.Update (Ctx, T.Buffer);
         Tux.HMAC.Finish_And_Verify (Ctx, HMAC, Valid);

         Assert (not Valid, "Invalid HMAC not detected");
      end Test_Finish_And_Verify_Invalid_First_Byte;

      -----------------------------------
      -- Test_Finish_And_Verify_Invalid_Last_Byte --
      -----------------------------------

      procedure Test_Finish_And_Verify_Invalid_Last_Byte (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key   : constant Tux.Types.Byte_Array (1 .. HLen) := (others => 0);
         HMAC  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.HMAC.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => HMAC);

         --  Corrupt a bit in the last byte
         HMAC (HMAC'Last) := HMAC (HMAC'Last) xor 2#1000_0000#;

         Tux.HMAC.Initialize (Ctx, Key);
         Tux.HMAC.Update (Ctx, T.Buffer);
         Tux.HMAC.Finish_And_Verify (Ctx, HMAC, Valid);

         Assert (not Valid, "Invalid HMAC not detected");
      end Test_Finish_And_Verify_Invalid_Last_Byte;

      ------------------
      -- Add_To_Suite --
      ------------------

      procedure Add_To_Suite (S : in out Test_Suite'Class) is
         Name : constant String :=
                  Tux.Hashing.Algorithm_Kind'Image (Algorithm);
      begin
         if Algorithm in Tux.Hashing.Enabled_Algorithm_Kind then
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (1 byte parts)",
                  Test_Multi_Part_1'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (2 byte parts)",
                  Test_Multi_Part_2'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (31 byte parts)",
                  Test_Multi_Part_31'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (32 byte parts)",
                  Test_Multi_Part_32'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (33 byte parts)",
                  Test_Multi_Part_33'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (63 byte parts)",
                  Test_Multi_Part_63'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (64 byte parts)",
                  Test_Multi_Part_64'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (65 byte parts)",
                  Test_Multi_Part_65'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (127 byte parts)",
                  Test_Multi_Part_127'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (128 byte parts)",
                  Test_Multi_Part_128'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " multi-part test (129 byte parts)",
                  Test_Multi_Part_129'Access));

            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test single-part HMAC Verify - "
                    & "valid hash",
                  Test_Verify_Valid_HMAC'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test single-part HMAC Verify - "
                    & "first byte corrupted",
                  Test_Verify_Invalid_First_Byte'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test single-part HMAC Verify - "
                    & "last byte corrupted",
                  Test_Verify_Invalid_Last_Byte'Access));

            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test multi-part HMAC Finish and Verify - "
                    & "valid hash",
                  Test_Finish_And_Verify_Valid_HMAC'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test multi-part HMAC Finish and Verify - "
                    & "first byte corrupted",
                  Test_Finish_And_Verify_Invalid_First_Byte'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test multi-part HMAC Finish and Verify - "
                    & "last byte corrupted",
                  Test_Finish_And_Verify_Invalid_Last_Byte'Access));
         end if;
      end Add_To_Suite;

   end Generic_HMAC_Tests;

end HMAC_Tests;
