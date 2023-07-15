--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types.Conversions; use Tux.Types.Conversions;

package body Tux.SHA1 with
  SPARK_Mode
is

   --===============--
   -- SHA Constants --
   --===============--

   Init_Constants : constant State_Array :=
     (0 => 16#6745_2301#,
      1 => 16#EFCD_AB89#,
      2 => 16#98BA_DCFE#,
      3 => 16#1032_5476#,
      4 => 16#C3D2_E1F0#);

   --======================--
   -- SHA round operations --
   --======================--

   subtype Schedule_Array is U32_Array (0 .. 15);
   subtype Round_Number is Natural range 0 .. 79;

   procedure Schedule
     (I :        Natural;
      W : in out Schedule_Array)
   with
     Inline_Always,
     Global  => null;

   generic
      with function F (B, C, D : Unsigned_32) return Unsigned_32;
      K : Unsigned_32;
   procedure Generic_Round
     (A     :        Unsigned_32;
      B     : in out Unsigned_32;
      C     :        Unsigned_32;
      D     :        Unsigned_32;
      E     : in out Unsigned_32;
      W     : in out Schedule_Array;
      Round :        Round_Number)
   with
     Inline_Always,
     Global => null;

   function F0 (B, C, D : Unsigned_32) return Unsigned_32 is
     ((B and C) or ((not B) and D));

   function F1 (B, C, D : Unsigned_32) return Unsigned_32 is
     (B xor C xor D);

   function F2 (B, C, D : Unsigned_32) return Unsigned_32 is
     ((B and C) xor (B and D) xor (C and D));

   procedure Schedule
     (I :        Natural;
      W : in out Schedule_Array)
   is
      Temp : Unsigned_32;
   begin
      Temp := W ((I - 3)  mod 16) xor
              W ((I - 8)  mod 16) xor
              W ((I - 14) mod 16) xor
              W (I        mod 16);
      W (I mod 16) := Rotate_Left (Temp, 1);
   end Schedule;

   procedure Generic_Round
     (A     :        Unsigned_32;
      B     : in out Unsigned_32;
      C     :        Unsigned_32;
      D     :        Unsigned_32;
      E     : in out Unsigned_32;
      W     : in out Schedule_Array;
      Round :        Round_Number)
   is
   begin
      if Round >= 16 then
         Schedule (Round, W);
      end if;

      E := E + Rotate_Left (A, 5) + F (B, C, D) + K + W (Round mod 16);
      B := Rotate_Left (B, 30);
   end Generic_Round;

   procedure Round_0 is new Generic_Round (F0, 16#5A82_7999#);
   procedure Round_1 is new Generic_Round (F1, 16#6ED9_EBA1#);
   procedure Round_2 is new Generic_Round (F2, 16#8F1B_BCDC#);
   procedure Round_3 is new Generic_Round (F1, 16#CA62_C1D6#);

   --============--
   -- Operations --
   --============--

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx.State                := Init_Constants;
      Ctx.Bytes_Processed      := 0;
      Ctx.Finished             := False;

      Block_Streaming.Initialize (Ctx.Buffer);
   end Initialize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
   begin
      Block_Streaming.Update (Ctx.Buffer, Data, Ctx.State);

      --  Update the message length.
      --
      --  Note that we assume here that the overall message length does not
      --  exceed 2**64 - 1 bits (2.306 exabytes) otherwise the length will
      --  wrap. This is a limitation of SHA-256's design.

      Ctx.Bytes_Processed := Ctx.Bytes_Processed + Unsigned_64 (Data'Length);
   end Update;

   ------------
   -- Finish --
   ------------

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Types.Byte_Array)
   is
      Length : Natural;
      Pos    : Natural;

      Length_Bits : Unsigned_64;

   begin
      --  Add padding bytes. 16#80# followed by zeroes then the last 8 bytes
      --  for the message length in bits.

      Length := Ctx.Buffer.Partial_Block_Length;

      Ctx.Buffer.Partial_Block (Length) := 16#80#;

      Length := Length + 1;

      if Length > 56 then
         --  Not enough space remaining for the length

         Ctx.Buffer.Partial_Block (Length .. 63) := (others => 0);
         Compress_Blocks (Ctx.State, Ctx.Buffer.Partial_Block);
         Ctx.Buffer.Partial_Block (0 .. 55) := (others => 0);
      else
         Ctx.Buffer.Partial_Block (Length .. 55) := (others => 0);
      end if;

      --  Add the length
      --
      --  We assume here that the overall message length does not exceed
      --  2**64 - 1 bits (approx. 2.306 exabytes). If this assumption is
      --  violated then the calculated length is modulo 2**64.

      Length_Bits := Ctx.Bytes_Processed * 8;
      To_Bytes_BE (Length_Bits, Ctx.Buffer.Partial_Block (56 .. 63));

      Compress_Blocks (Ctx.State, Ctx.Buffer.Partial_Block);

      pragma Assert_And_Cut (Hash'Length = SHA1_Hash_Length);

      --  Output the digest

      Pos := Hash'First;
      To_Bytes_BE (Ctx.State (0), Hash (Pos      .. Pos +  3));
      To_Bytes_BE (Ctx.State (1), Hash (Pos + 4  .. Pos +  7));
      To_Bytes_BE (Ctx.State (2), Hash (Pos + 8  .. Pos + 11));
      To_Bytes_BE (Ctx.State (3), Hash (Pos + 12 .. Pos + 15));
      To_Bytes_BE (Ctx.State (4), Hash (Pos + 16 .. Pos + 19));

      Sanitize (Ctx.State);
      Block_Streaming.Sanitize (Ctx.Buffer);

      Ctx.Finished := True;
   end Finish;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      Sanitize (Ctx.State);
      Ctx.Bytes_Processed := 0;
      Ctx.Finished        := True;
      Block_Streaming.Sanitize (Ctx.Buffer);
   end Sanitize;

   ------------------
   -- Compute_Hash --
   ------------------

   procedure Compute_Hash
     (Data :     Byte_Array;
      Hash : out Byte_Array)
   is
      Ctx : Context;
   begin
      Initialize (Ctx);
      Update (Ctx, Data);
      Finish (Ctx, Hash); --  Sanitizes Ctx

      pragma Unreferenced (Ctx);
   end Compute_Hash;

   -----------------
   -- Verify_Hash --
   -----------------

   function Verify_Hash
     (Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   is
      Hash  : SHA1_Hash;
      Valid : Boolean;

   begin
      Compute_Hash (Data, Hash);

      Valid :=  Equal_Constant_Time
                  (Expected_Hash, Hash (1 .. Expected_Hash'Length));

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Hash);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Hash);

      return Valid;
   end Verify_Hash;

   ---------------------
   -- Compress_Blocks --
   ---------------------

   procedure Compress_Blocks
     (State : in out State_Array;
      Blocks :        Byte_Array)
   is
      Remaining : Byte_Count := Blocks'Length;
      Offset    : Byte_Count := 0;

      Pos : Natural;

      W : Schedule_Array with Relaxed_Initialization;

      A : Unsigned_32;
      B : Unsigned_32;
      C : Unsigned_32;
      D : Unsigned_32;
      E : Unsigned_32;

   begin
      while Remaining > 0 loop
         pragma Loop_Variant (Decreases => Remaining);
         pragma Loop_Invariant (Offset + Remaining = Blocks'Length);
         pragma Loop_Invariant (Remaining mod Block_Length = 0);

         A := State (0);
         B := State (1);
         C := State (2);
         D := State (3);
         E := State (4);

         for I in Natural range Schedule_Array'Range loop
            pragma Warnings
              (GNAT, Off,
               """W"" may be referenced before it has a value",
               Reason => "Initialization of W is verified via proof");
            pragma Loop_Invariant (W (0 .. I - 1)'Initialized);
            pragma Warnings (GNAT, On);

            Pos   := Blocks'First + Offset + (I * 4);
            W (I) := To_U32_BE (Blocks (Pos .. Pos + 3));
         end loop;

         Round_0 (A, B, C, D, E, W, 0);
         Round_0 (E, A, B, C, D, W, 1);
         Round_0 (D, E, A, B, C, W, 2);
         Round_0 (C, D, E, A, B, W, 3);
         Round_0 (B, C, D, E, A, W, 4);
         Round_0 (A, B, C, D, E, W, 5);
         Round_0 (E, A, B, C, D, W, 6);
         Round_0 (D, E, A, B, C, W, 7);
         Round_0 (C, D, E, A, B, W, 8);
         Round_0 (B, C, D, E, A, W, 9);
         Round_0 (A, B, C, D, E, W, 10);
         Round_0 (E, A, B, C, D, W, 11);
         Round_0 (D, E, A, B, C, W, 12);
         Round_0 (C, D, E, A, B, W, 13);
         Round_0 (B, C, D, E, A, W, 14);
         Round_0 (A, B, C, D, E, W, 15);
         Round_0 (E, A, B, C, D, W, 16);
         Round_0 (D, E, A, B, C, W, 17);
         Round_0 (C, D, E, A, B, W, 18);
         Round_0 (B, C, D, E, A, W, 19);

         Round_1 (A, B, C, D, E, W, 20);
         Round_1 (E, A, B, C, D, W, 21);
         Round_1 (D, E, A, B, C, W, 22);
         Round_1 (C, D, E, A, B, W, 23);
         Round_1 (B, C, D, E, A, W, 24);
         Round_1 (A, B, C, D, E, W, 25);
         Round_1 (E, A, B, C, D, W, 26);
         Round_1 (D, E, A, B, C, W, 27);
         Round_1 (C, D, E, A, B, W, 28);
         Round_1 (B, C, D, E, A, W, 29);
         Round_1 (A, B, C, D, E, W, 30);
         Round_1 (E, A, B, C, D, W, 31);
         Round_1 (D, E, A, B, C, W, 32);
         Round_1 (C, D, E, A, B, W, 33);
         Round_1 (B, C, D, E, A, W, 34);
         Round_1 (A, B, C, D, E, W, 35);
         Round_1 (E, A, B, C, D, W, 36);
         Round_1 (D, E, A, B, C, W, 37);
         Round_1 (C, D, E, A, B, W, 38);
         Round_1 (B, C, D, E, A, W, 39);

         Round_2 (A, B, C, D, E, W, 40);
         Round_2 (E, A, B, C, D, W, 41);
         Round_2 (D, E, A, B, C, W, 42);
         Round_2 (C, D, E, A, B, W, 43);
         Round_2 (B, C, D, E, A, W, 44);
         Round_2 (A, B, C, D, E, W, 45);
         Round_2 (E, A, B, C, D, W, 46);
         Round_2 (D, E, A, B, C, W, 47);
         Round_2 (C, D, E, A, B, W, 48);
         Round_2 (B, C, D, E, A, W, 49);
         Round_2 (A, B, C, D, E, W, 50);
         Round_2 (E, A, B, C, D, W, 51);
         Round_2 (D, E, A, B, C, W, 52);
         Round_2 (C, D, E, A, B, W, 53);
         Round_2 (B, C, D, E, A, W, 54);
         Round_2 (A, B, C, D, E, W, 55);
         Round_2 (E, A, B, C, D, W, 56);
         Round_2 (D, E, A, B, C, W, 57);
         Round_2 (C, D, E, A, B, W, 58);
         Round_2 (B, C, D, E, A, W, 59);

         Round_3 (A, B, C, D, E, W, 60);
         Round_3 (E, A, B, C, D, W, 61);
         Round_3 (D, E, A, B, C, W, 62);
         Round_3 (C, D, E, A, B, W, 63);
         Round_3 (B, C, D, E, A, W, 64);
         Round_3 (A, B, C, D, E, W, 65);
         Round_3 (E, A, B, C, D, W, 66);
         Round_3 (D, E, A, B, C, W, 67);
         Round_3 (C, D, E, A, B, W, 68);
         Round_3 (B, C, D, E, A, W, 69);
         Round_3 (A, B, C, D, E, W, 70);
         Round_3 (E, A, B, C, D, W, 71);
         Round_3 (D, E, A, B, C, W, 72);
         Round_3 (C, D, E, A, B, W, 73);
         Round_3 (B, C, D, E, A, W, 74);
         Round_3 (A, B, C, D, E, W, 75);
         Round_3 (E, A, B, C, D, W, 76);
         Round_3 (D, E, A, B, C, W, 77);
         Round_3 (C, D, E, A, B, W, 78);
         Round_3 (B, C, D, E, A, W, 79);

         State (0) := State (0) + A;
         State (1) := State (1) + B;
         State (2) := State (2) + C;
         State (3) := State (3) + D;
         State (4) := State (4) + E;

         Offset    := Offset    + Block_Length;
         Remaining := Remaining - Block_Length;
      end loop;

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (W);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (W);
   end Compress_Blocks;

end Tux.SHA1;
