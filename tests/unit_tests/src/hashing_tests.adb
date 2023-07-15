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
              "Multi-part hash does not match single-part hash");
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
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Hash);
         Valid := Tux.Hashing.Verify_Hash (Algorithm, T.Buffer, Hash);
         Assert (Valid, "Hash verify failed");
      end Test_Verify_Valid_Hash;

      ------------------------------------
      -- Test_Verify_Invalid_First_Byte --
      ------------------------------------

      procedure Test_Verify_Invalid_First_Byte (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the first byte
         Hash (Hash'First) := Hash (Hash'First) xor 1;

         Valid := Tux.Hashing.Verify_Hash (Algorithm, T.Buffer, Hash);
         Assert (not Valid, "Invalid hash not detected");
      end Test_Verify_Invalid_First_Byte;

      -----------------------------------
      -- Test_Verify_Invalid_Last_Byte --
      -----------------------------------

      procedure Test_Verify_Invalid_Last_Byte (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the last byte
         Hash (Hash'Last) := Hash (Hash'Last) xor 2#1000_0000#;

         Valid := Tux.Hashing.Verify_Hash (Algorithm, T.Buffer, Hash);
         Assert (not Valid, "Invalid hash not detected");
      end Test_Verify_Invalid_Last_Byte;

      -----------------------------------
      -- Test_Finish_Verify_Valid_Hash --
      -----------------------------------

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

      -------------------------------------------
      -- Test_Finish_Verify_Invalid_First_Byte --
      -------------------------------------------

      procedure Test_Finish_Verify_Invalid_First_Byte (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.Hashing.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the first byte
         Hash (Hash'First) := Hash (Hash'First) xor 1;

         Tux.Hashing.Initialize (Ctx);
         Tux.Hashing.Update (Ctx, T.Buffer);
         Tux.Hashing.Finish_And_Verify (Ctx, Hash, Valid);

         Assert (not Valid, "Invalid hash not detected");
      end Test_Finish_Verify_Invalid_First_Byte;

      ------------------------------------------
      -- Test_Finish_Verify_Invalid_Last_Byte --
      ------------------------------------------

      procedure Test_Finish_Verify_Invalid_Last_Byte (T : in out Test) is
         HLen  : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Ctx   : Tux.Hashing.Context (Algorithm);
         Valid : Boolean;

      begin
         Tux.Hashing.Compute_Hash (Algorithm, T.Buffer, Hash);

         --  Corrupt a bit in the last byte
         Hash (Hash'Last) := Hash (Hash'Last) xor 2#1000_0000#;

         Tux.Hashing.Initialize (Ctx);
         Tux.Hashing.Update (Ctx, T.Buffer);
         Tux.Hashing.Finish_And_Verify (Ctx, Hash, Valid);

         Assert (not Valid, "Invalid hash not detected");
      end Test_Finish_Verify_Invalid_Last_Byte;

      ------------------
      -- Add_To_Suite --
      ------------------

      procedure Add_To_Suite (S : in out Test_Suite'Class) is
         Name : constant String :=
                  Tux.Hashing.Algorithm_Kind'Image (Algorithm);
      begin
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
              (Name & " test multi-part hash finish & verify - valid hash",
               Test_Finish_Verify_Valid_Hash'Access));
         S.Add_Test
           (Caller.Create
              (Name & " test multi-part hash finish & verify - "
                 & "first byte corrupted",
               Test_Finish_Verify_Invalid_First_Byte'Access));
         S.Add_Test
           (Caller.Create
              (Name & " test multi-part hash finish & verify - "
                 & "last byte corrupted",
               Test_Finish_Verify_Invalid_Last_Byte'Access));
      end Add_To_Suite;

   end Generic_Hashing_Tests;

   -----------
   -- Suite --
   -----------

   package SHA1_Multi_Part_Tests is new Generic_Hashing_Tests
     (Tux.Hashing.SHA1);

   package SHA224_Multi_Part_Tests is new Generic_Hashing_Tests
     (Tux.Hashing.SHA224);

   package SHA256_Multi_Part_Tests is new Generic_Hashing_Tests
     (Tux.Hashing.SHA256);

   package SHA384_Multi_Part_Tests is new Generic_Hashing_Tests
     (Tux.Hashing.SHA384);

   package SHA512_Multi_Part_Tests is new Generic_Hashing_Tests
     (Tux.Hashing.SHA512);

   package SHA512_224_Multi_Part_Tests is new Generic_Hashing_Tests
     (Tux.Hashing.SHA512_224);

   package SHA512_256_Multi_Part_Tests is new Generic_Hashing_Tests
     (Tux.Hashing.SHA512_256);

   function Suite return Access_Test_Suite is
      S : constant Access_Test_Suite := new Test_Suite;
   begin

      SHA1_Multi_Part_Tests.Add_To_Suite (S.all);
      SHA224_Multi_Part_Tests.Add_To_Suite (S.all);
      SHA256_Multi_Part_Tests.Add_To_Suite (S.all);
      SHA384_Multi_Part_Tests.Add_To_Suite (S.all);
      SHA512_Multi_Part_Tests.Add_To_Suite (S.all);
      SHA512_224_Multi_Part_Tests.Add_To_Suite (S.all);
      SHA512_256_Multi_Part_Tests.Add_To_Suite (S.all);

      return S;
   end Suite;

end Hashing_Tests;
