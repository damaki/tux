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
              "Incorrect MAC when Part_Length =" & Part_Length'Image);
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

      ---------------------
      -- Test_Multi_Part --
      ---------------------

      --  This test verifies that processing a large message in differently
      --  sized parts produces the same MAC as processing the entire message
      --  in a single part.

      procedure Test_Multi_Part (T : in out Test) is
      begin
         for I in Positive range 1 .. 256 loop
            Multi_Part_Test (T.Buffer, Algorithm, I);
         end loop;
      end Test_Multi_Part;

      ----------------------------
      -- Test_Verify_Valid_HMAC --
      ----------------------------

      --  This test verifies that the Verify_HMAC function returns True when
      --  presented with a valid MAC.

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

      ------------------------------
      -- Test_Verify_Invalid_HMAC --
      ------------------------------

      --  This test verifies that Verify_MAC returns False when presented with
      --  an invalid MAC.
      --
      --  The test is repeated for all possible 1-bit errors in the MAC.

      procedure Test_Verify_Invalid_HMAC (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key          : constant Tux.Types.Byte_Array (1 .. HLen) :=
                          (others => 0);
         Valid_HMAC   : Tux.Types.Byte_Array (1 .. HLen);
         Invalid_HMAC : Tux.Types.Byte_Array (1 .. HLen);
         Valid        : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => Valid_HMAC);

         for Byte_Idx in Tux.Types.Byte_Count range 1 .. HLen loop
            for Bit_Idx in Natural range 0 .. 7 loop

               Invalid_HMAC := Valid_HMAC;

               Invalid_HMAC (Byte_Idx) :=
                 Invalid_HMAC (Byte_Idx) xor Shift_Left (1, Bit_Idx);

               Valid := Tux.HMAC.Verify_HMAC
                        (Algorithm    => Algorithm,
                         Key          => Key,
                         Data         => T.Buffer,
                         Expected_MAC => Invalid_HMAC);

               Assert (not Valid,
                       "Invalid HMAC not detected when bit" & Bit_Idx'Image &
                       " in byte" & Byte_Idx'Image & " is corrupted");
            end loop;
         end loop;
      end Test_Verify_Invalid_HMAC;

      ---------------------------------------
      -- Test_Finish_And_Verify_Valid_HMAC --
      ---------------------------------------

      --  This test verifies that the Finish_And_Verify outputs returns True
      --  when presented with a valid MAC.

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

      -----------------------------------------
      -- Test_Finish_And_Verify_Invalid_HMAC --
      -----------------------------------------

      --  This test verifies that Finish_And_Verify outputs False when
      --  presented with an invalid MAC.
      --
      --  The test is repeated for all possible 1-bit errors in the MAC.

      procedure Test_Finish_And_Verify_Invalid_HMAC (T : in out Test) is
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algorithm);

         Key : constant Tux.Types.Byte_Array (1 .. HLen) := (others => 0);

         Valid_HMAC   : Tux.Types.Byte_Array (1 .. HLen);
         Invalid_HMAC : Tux.Types.Byte_Array (1 .. HLen);
         Ctx          : Tux.HMAC.Context (Algorithm);
         Valid        : Boolean;

      begin
         Tux.HMAC.Compute_HMAC
           (Algorithm => Algorithm,
            Key       => Key,
            Data      => T.Buffer,
            MAC       => Valid_HMAC);

         for Byte_Idx in Tux.Types.Index_Number range 1 .. HLen loop
            for Bit_Idx in Natural range 0 .. 7 loop

               Invalid_HMAC := Valid_HMAC;

               Invalid_HMAC (Byte_Idx) :=
                 Invalid_HMAC (Byte_Idx) xor Shift_Left (1, Bit_Idx);

               Tux.HMAC.Initialize (Ctx, Key);
               Tux.HMAC.Update (Ctx, T.Buffer);
               Tux.HMAC.Finish_And_Verify (Ctx, Invalid_HMAC, Valid);

               Assert (not Valid,
                       "Invalid HMAC not detected when bit" & Bit_Idx'Image &
                       " in byte" & Byte_Idx'Image & " is corrupted");
            end loop;
         end loop;
      end Test_Finish_And_Verify_Invalid_HMAC;

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
                 ("HMAC-" & Name & " multi-part test",
                  Test_Multi_Part'Access));

            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test single-part HMAC Verify - "
                    & "valid hash",
                  Test_Verify_Valid_HMAC'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test single-part HMAC Verify - "
                    & "invalid hash",
                  Test_Verify_Invalid_HMAC'Access));

            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test multi-part HMAC Finish and Verify - "
                    & "valid hash",
                  Test_Finish_And_Verify_Valid_HMAC'Access));
            S.Add_Test
              (Caller.Create
                 ("HMAC-" & Name & " test multi-part HMAC Finish and Verify - "
                    & "invalid hash",
                  Test_Finish_And_Verify_Invalid_HMAC'Access));
         end if;
      end Add_To_Suite;

   end Generic_HMAC_Tests;

end HMAC_Tests;
