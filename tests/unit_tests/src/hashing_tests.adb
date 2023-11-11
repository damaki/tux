--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;
with Interfaces;       use Interfaces;

package body Hashing_Tests is

   ---------------------
   -- Multi_Part_Test --
   ---------------------

   procedure Multi_Part_Test
     (Buffer      : Tux.Types.Byte_Array;
      Algorithm   : Tux.Hashing.Algorithm_Kind;
      Part_Length : Positive)
   is
      use type Tux.Types.Byte_Array;

      HLen : constant Tux.Hashing.Hash_Length_Number :=
               Tux.Hashing.Hash_Length (Algorithm);

      Hash           : Tux.Types.Byte_Array (1 .. HLen);
      Reference_Hash : Tux.Types.Byte_Array (1 .. HLen);

      Ctx : Tux.Hashing.Context (Algorithm);

      Offset    : Natural := 0;
      Remaining : Natural := Buffer'Length;
      Pos       : Tux.Types.Index_Number;

   begin
      Tux.Hashing.Compute_Hash (Algorithm, Buffer, Reference_Hash);

      Tux.Hashing.Initialize (Ctx);

      while Remaining >= Part_Length loop
         pragma Loop_Invariant (Offset + Remaining = Buffer'Length);

         Pos := Buffer'First + Offset;

         Tux.Hashing.Update (Ctx, Buffer (Pos .. Pos + Part_Length - 1));

         Offset    := Offset    + Part_Length;
         Remaining := Remaining - Part_Length;
      end loop;

      Tux.Hashing.Update (Ctx, Buffer (Buffer'First + Offset .. Buffer'Last));
      Tux.Hashing.Finish (Ctx, Hash);

      Assert (Hash = Reference_Hash,
              "Incorrect hash when Part_Length =" & Part_Length'Image);
   end Multi_Part_Test;

   ----------------------------------
   -- Generic_Hashing_Tests (body) --
   ----------------------------------

   package body Generic_Hashing_Tests is

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
      --  sized parts produces the same hash as processing the entire message
      --  in a single part.

      procedure Test_Multi_Part (T : in out Test) is
      begin
         for Part_Length in Tux.Types.Byte_Count range 1 .. 256 loop
            Multi_Part_Test (T.Buffer, Algorithm, 1);
         end loop;
      end Test_Multi_Part;

      ----------------------------
      -- Test_Verify_Valid_Hash --
      ----------------------------

      --  This test verifies that the Verify_Hash function returns True when
      --  presented with a valid hash.

      procedure Test_Verify_Valid_Hash (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Hash);
         Valid := Tux.Hashing.Verify_Hash (Algorithm, T.Buffer, Hash);
         Assert (Valid, "Hash verify failed");
      end Test_Verify_Valid_Hash;

      ------------------------------
      -- Test_Verify_Invalid_Hash --
      ------------------------------

      --  This test verifies that Verify_Hash returns False when presented with
      --  an invalid hash.
      --
      --  The test is repeated for all possible 1-bit errors in the hash.

      procedure Test_Verify_Invalid_Hash (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);

         Valid_Hash   : Tux.Types.Byte_Array (1 .. HLen);
         Invalid_Hash : Tux.Types.Byte_Array (1 .. HLen);
         Valid        : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Valid_Hash);

         for Byte_Idx in Tux.Types.Byte_Count range 1 .. HLen loop
            for Bit_Idx in Natural range 0 .. 7 loop

               Invalid_Hash := Valid_Hash;

               Invalid_Hash (Byte_Idx) :=
                 Invalid_Hash (Byte_Idx) xor Shift_Left (1, Bit_Idx);

               Valid := Tux.Hashing.Verify_Hash
                          (Algorithm, T.Buffer, Invalid_Hash);

               Assert (not Valid,
                       "Invalid hash not detected when bit" & Bit_Idx'Image &
                       " in byte" & Byte_Idx'Image & " is corrupted");
            end loop;
         end loop;
      end Test_Verify_Invalid_Hash;

      -----------------------------------
      -- Test_Finish_Verify_Valid_Hash --
      -----------------------------------

      --  This test verifies that the Finish_And_Verify function returns True
      --  when presented with a valid hash.

      procedure Test_Finish_Verify_Valid_Hash (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.Hashing.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Hash);

         Tux.Hashing.Initialize (Ctx);
         Tux.Hashing.Update (Ctx, T.Buffer);
         Tux.Hashing.Finish_And_Verify (Ctx, Hash, Valid);

         Assert (Valid, "Hash verify failed");
      end Test_Finish_Verify_Valid_Hash;

      -------------------------------------
      -- Test_Finish_Verify_Invalid_Hash --
      -------------------------------------

      --  This test verifies that Finish_And_Verify outputs False when
      --  presented with an invalid hash.
      --
      --  The test is repeated for all possible 1-bit errors in the hash.

      procedure Test_Finish_Verify_Invalid_Hash (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);

         Ctx          : Tux.Hashing.Context (Algorithm);
         Valid_Hash   : Tux.Types.Byte_Array (1 .. HLen);
         Invalid_Hash : Tux.Types.Byte_Array (1 .. HLen);
         Valid        : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Valid_Hash);

         for Byte_Idx in Tux.Types.Byte_Count range 1 .. HLen loop
            for Bit_Idx in Natural range 0 .. 7 loop

               Invalid_Hash := Valid_Hash;

               Invalid_Hash (Byte_Idx) :=
                 Invalid_Hash (Byte_Idx) xor Shift_Left (1, Bit_Idx);

               Tux.Hashing.Initialize (Ctx);
               Tux.Hashing.Update (Ctx, T.Buffer);
               Tux.Hashing.Finish_And_Verify (Ctx, Invalid_Hash, Valid);

               Assert (not Valid,
                       "Invalid hash not detected when bit" & Bit_Idx'Image &
                       " in byte" & Byte_Idx'Image & " is corrupted");
            end loop;
         end loop;
      end Test_Finish_Verify_Invalid_Hash;

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
                 (Name & " multi-part test",
                  Test_Multi_Part'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " test single-part hash verify - valid hash",
                  Test_Verify_Valid_Hash'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " test single-part hash verify - invalid hash",
                  Test_Verify_Invalid_Hash'Access));

            S.Add_Test
              (Caller.Create
                 (Name &
                    " test multi-part hash finish and verify - valid hash",
                  Test_Finish_Verify_Valid_Hash'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " test multi-part hash finish and verify - "
                    & "invalid hash",
                  Test_Finish_Verify_Invalid_Hash'Access));
         end if;
      end Add_To_Suite;

   end Generic_Hashing_Tests;

end Hashing_Tests;
