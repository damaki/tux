--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with AUnit.Assertions; use AUnit.Assertions;
with Interfaces;       use Interfaces;

package body XOF_Tests is

   ---------------------
   -- Multi_Part_Test --
   ---------------------

   procedure Multi_Part_Test
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

      Offset    := 0;
      Remaining := Hash'Length;

      while Remaining >= Part_Length loop
         pragma Loop_Invariant (Offset + Remaining = Hash'Length);

         Pos := Hash'First + Offset;

         Tux.XOF.Extract (Ctx, Hash (Pos .. Pos + Part_Length - 1));

         Offset    := Offset    + Part_Length;
         Remaining := Remaining - Part_Length;
      end loop;

      Assert (Hash = Reference_Hash,
              "Multi-part hash does not match single-part hash");
   end Multi_Part_Test;

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

      ------------------------------
      -- Multi-part Message Tests --
      ------------------------------

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
      -- Test_Verify_Valid_Hash --
      ----------------------------

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

      ------------------------------------
      -- Test_Verify_Invalid_First_Byte --
      ------------------------------------

      procedure Test_Verify_Invalid_First_Byte (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the first byte
         Hash (Hash'First) := Hash (Hash'First) xor 1;

         Valid := Tux.XOF.Verify_Digest (Algorithm, T.Buffer, Hash);
         Assert (not Valid, "Invalid hash not detected");
      end Test_Verify_Invalid_First_Byte;

      -----------------------------------
      -- Test_Verify_Invalid_Last_Byte --
      -----------------------------------

      procedure Test_Verify_Invalid_Last_Byte (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the last byte
         Hash (Hash'Last) := Hash (Hash'Last) xor 2#1000_0000#;

         Valid := Tux.XOF.Verify_Digest (Algorithm, T.Buffer, Hash);
         Assert (not Valid, "Invalid hash not detected");
      end Test_Verify_Invalid_Last_Byte;

      -----------------------------------
      -- Test_Finish_Verify_Valid_Hash --
      -----------------------------------

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

      -------------------------------------------
      -- Test_Finish_Verify_Invalid_First_Byte --
      -------------------------------------------

      procedure Test_Finish_Verify_Invalid_First_Byte (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.XOF.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the first byte
         Hash (Hash'First) := Hash (Hash'First) xor 1;

         Tux.XOF.Initialize (Ctx);
         Tux.XOF.Update (Ctx, T.Buffer);
         Tux.XOF.Extract_And_Verify (Ctx, Hash, Valid);

         Assert (not Valid, "Invalid hash not detected");
      end Test_Finish_Verify_Invalid_First_Byte;

      ------------------------------------------
      -- Test_Finish_Verify_Invalid_Last_Byte --
      ------------------------------------------

      procedure Test_Finish_Verify_Invalid_Last_Byte (T : in out Test) is
         HLen  : constant Tux.XOF.Block_Length_Number :=
                   Tux.XOF.Block_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.XOF.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.XOF.Compute_Digest (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the last byte
         Hash (Hash'Last) := Hash (Hash'Last) xor 2#1000_0000#;

         Tux.XOF.Initialize (Ctx);
         Tux.XOF.Update (Ctx, T.Buffer);
         Tux.XOF.Extract_And_Verify (Ctx, Hash, Valid);

         Assert (not Valid, "Invalid hash not detected");
      end Test_Finish_Verify_Invalid_Last_Byte;

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
                 (Name & " multi-part test (1 byte parts)",
                  Test_Multi_Part_1'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (2 byte parts)",
                  Test_Multi_Part_2'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (31 byte parts)",
                  Test_Multi_Part_31'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (32 byte parts)",
                  Test_Multi_Part_32'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (33 byte parts)",
                  Test_Multi_Part_33'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (63 byte parts)",
                  Test_Multi_Part_63'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (64 byte parts)",
                  Test_Multi_Part_64'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (65 byte parts)",
                  Test_Multi_Part_65'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (127 byte parts)",
                  Test_Multi_Part_127'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (128 byte parts)",
                  Test_Multi_Part_128'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " multi-part test (129 byte parts)",
                  Test_Multi_Part_129'Access));

            S.Add_Test
              (Caller.Create
                 (Name & " test single-part hash verify - valid hash",
                  Test_Verify_Valid_Hash'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " test single-part hash verify - byte corrupted",
                  Test_Verify_Invalid_First_Byte'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " test single-part hash verify - last byte corrupted",
                  Test_Verify_Invalid_Last_Byte'Access));

            S.Add_Test
              (Caller.Create
                 (Name &
                    " test multi-part hash finish and verify - valid hash",
                  Test_Finish_Verify_Valid_Hash'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " test multi-part hash finish and verify - "
                    & "first byte corrupted",
                  Test_Finish_Verify_Invalid_First_Byte'Access));
            S.Add_Test
              (Caller.Create
                 (Name & " test multi-part hash finish and verify - "
                    & "last byte corrupted",
                  Test_Finish_Verify_Invalid_Last_Byte'Access));
         end if;
      end Add_To_Suite;

   end Generic_XOF_Tests;

end XOF_Tests;
