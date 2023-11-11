--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;
with Interfaces;       use Interfaces;

package body XOF_Tests is

   ---------------------------
   -- Multi_Part_Input_Test --
   ---------------------------

   procedure Multi_Part_Input_Test
     (Buffer      : Tux.Types.Byte_Array;
      Algorithm   : Tux.XOF.Algorithm_Kind;
      Part_Length : Positive)
   is
      use type Tux.Types.Byte_Array;

      Hash           : Tux.Types.Byte_Array (1 .. Part_Length * 4);
      Reference_Hash : Tux.Types.Byte_Array (1 .. Part_Length * 4);

      Ctx : Tux.XOF.Context (Algorithm);

      Offset    : Natural := 0;
      Remaining : Natural := Buffer'Length;
      Pos       : Tux.Types.Index_Number;

   begin
      Tux.XOF.Compute_Digest (Algorithm, Buffer, Reference_Hash);

      Tux.XOF.Initialize (Ctx);

      while Remaining >= Part_Length loop
         pragma Loop_Invariant (Offset + Remaining = Buffer'Length);

         Pos := Buffer'First + Offset;

         Tux.XOF.Update (Ctx, Buffer (Pos .. Pos + Part_Length - 1));

         Offset    := Offset    + Part_Length;
         Remaining := Remaining - Part_Length;
      end loop;

      Tux.XOF.Update (Ctx, Buffer (Buffer'First + Offset .. Buffer'Last));
      Tux.XOF.Extract (Ctx, Hash);

      Assert (Hash = Reference_Hash,
              "Multi-part hash does not match single-part hash");
   end Multi_Part_Input_Test;

   ----------------------------
   -- Multi_Part_Output_Test --
   ----------------------------

   procedure Multi_Part_Output_Test
     (Hash           : in out Tux.Types.Byte_Array;
      Reference_Hash : in out Tux.Types.Byte_Array;
      Algorithm      :        Tux.XOF.Algorithm_Kind;
      Part_Length    :        Positive)
   is
      use type Tux.Types.Byte_Array;

      Ctx : Tux.XOF.Context (Algorithm);

      Offset    : Natural := 0;
      Remaining : Natural := Hash'Length;
      Pos       : Tux.Types.Index_Number;

   begin
      Tux.XOF.Compute_Digest
        (Algorithm, Tux.Types.Empty_Byte_Array, Reference_Hash);

      Tux.XOF.Initialize (Ctx);

      while Remaining >= Part_Length loop
         pragma Loop_Invariant (Offset + Remaining = Hash'Length);

         Pos := Hash'First + Offset;

         Tux.XOF.Extract (Ctx, Hash (Pos .. Pos + Part_Length - 1));

         Offset    := Offset    + Part_Length;
         Remaining := Remaining - Part_Length;
      end loop;

      if Remaining > 0 then
         Tux.XOF.Extract (Ctx, Hash (Hash'First + Offset .. Hash'Last));
      end if;

      Assert (Hash = Reference_Hash,
              "Multi-part hash does not match single-part hash");
   end Multi_Part_Output_Test;

   ----------------------------------
   -- Generic_XOF_Tests (body) --
   ----------------------------------

   package body Generic_XOF_Tests is

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

      ---------------------------
      -- Test_Multi_Part_Input --
      ---------------------------

      --  This test verifies that processing a large input message in
      --  differently sized parts produces the same hash as processing the
      --  entire message in a single part.

      procedure Test_Multi_Part_Input (T : in out Test) is
      begin
         for Part_Length in Tux.Types.Byte_Count range 1 .. 256 loop
            Multi_Part_Input_Test (T.Buffer, Algorithm, Part_Length);
         end loop;
      end Test_Multi_Part_Input;

      ----------------------------
      -- Test_Multi_Part_Output --
      ----------------------------

      --  This test verifies that extracting a large multi-part hash in
      --  differently sized parts produces the same hash as getting the output
      --  as a single part.

      procedure Test_Multi_Part_Output (T : in out Test) is
         HLen : constant Tux.Types.Byte_Count := T.Buffer'Length / 2;
      begin
         for Part_Length in Tux.Types.Byte_Count range 1 .. 256 loop
            Multi_Part_Output_Test
              (Hash           => T.Buffer (1 .. HLen),
               Reference_Hash => T.Buffer (HLen + 1 .. T.Buffer'Last),
               Algorithm      => Algorithm,
               Part_Length    => Part_Length);
         end loop;
      end Test_Multi_Part_Output;

      ----------------------------
      -- Test_Verify_Valid_Hash --
      ----------------------------

      --  This test verifies that the Verify_Digest function returns True when
      --  presented with a valid hash.

      procedure Test_Verify_Valid_Hash (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Hash);
         Valid := Tux.XOF.Verify_Digest (Algorithm, T.Buffer, Hash);
         Assert (Valid, "Hash verify failed");
      end Test_Verify_Valid_Hash;

      ------------------------------
      -- Test_Verify_Invalid_Hash --
      ------------------------------

      --  This test verifies that Verify_Digest returns False when presented
      --  with an invalid hash.
      --
      --  The test is repeated for all possible 1-bit errors in the hash.

      procedure Test_Verify_Invalid_Hash (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);

         Valid_Hash   : Tux.Types.Byte_Array (1 .. HLen);
         Invalid_Hash : Tux.Types.Byte_Array (1 .. HLen);
         Valid        : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Valid_Hash);

         for Byte_Idx in Tux.Types.Byte_Count range 1 .. HLen loop
            for Bit_Idx in Natural range 0 .. 7 loop

               Invalid_Hash := Valid_Hash;

               Invalid_Hash (Byte_Idx) :=
                 Invalid_Hash (Byte_Idx) xor Shift_Left (1, Bit_Idx);

               Valid := Tux.XOF.Verify_Digest
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

      --  This test verifies that the Extract_And_Verify function returns True
      --  when presented with a valid hash.

      procedure Test_Finish_Verify_Valid_Hash (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.XOF.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Hash);

         Tux.XOF.Initialize (Ctx);
         Tux.XOF.Update (Ctx, T.Buffer);
         Tux.XOF.Extract_And_Verify (Ctx, Hash, Valid);

         Assert (Valid, "Hash verify failed");
      end Test_Finish_Verify_Valid_Hash;

      -------------------------------------
      -- Test_Finish_Verify_Invalid_Hash --
      -------------------------------------

      --  This test verifies that Extract_And_Verify outputs False when
      --  presented with an invalid hash.
      --
      --  The test is repeated for all possible 1-bit errors in the hash.

      procedure Test_Finish_Verify_Invalid_Hash (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);

         Valid_Hash   : Tux.Types.Byte_Array (1 .. HLen);
         Invalid_Hash : Tux.Types.Byte_Array (1 .. HLen);
         Ctx          : Tux.XOF.Context (Algorithm);
         Valid        : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Valid_Hash);

         for Byte_Idx in Tux.Types.Byte_Count range 1 .. HLen loop
            for Bit_Idx in Natural range 0 .. 7 loop

               Invalid_Hash := Valid_Hash;

               Invalid_Hash (Byte_Idx) :=
                 Invalid_Hash (Byte_Idx) xor Shift_Left (1, Bit_Idx);

               Tux.XOF.Initialize (Ctx);
               Tux.XOF.Update (Ctx, T.Buffer);
               Tux.XOF.Extract_And_Verify (Ctx, Invalid_Hash, Valid);

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
                  Tux.XOF.Algorithm_Kind'Image (Algorithm);
      begin
         if Algorithm in Tux.XOF.Enabled_Algorithm_Kind then
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part input test",
                  Test_Multi_Part_Input'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part output test",
                  Test_Multi_Part_Output'Access));
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

   end Generic_XOF_Tests;

end XOF_Tests;
