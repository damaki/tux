--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types.Conversions; use Tux.Types.Conversions;

package body Tux.SHA256 with
  SPARK_Mode
is

   --====================--
   -- Common Definitions --
   --====================--

   -----------------------
   -- SHA-256 Constants --
   -----------------------

   Round_K : constant Types.U32_Array (0 .. 63) :=
     (16#428A2F98#, 16#71374491#, 16#B5C0FBCF#, 16#E9B5DBA5#,
      16#3956C25B#, 16#59F111F1#, 16#923F82A4#, 16#AB1C5ED5#,
      16#D807AA98#, 16#12835B01#, 16#243185BE#, 16#550C7DC3#,
      16#72BE5D74#, 16#80DEB1FE#, 16#9BDC06A7#, 16#C19BF174#,
      16#E49B69C1#, 16#EFBE4786#, 16#0FC19DC6#, 16#240CA1CC#,
      16#2DE92C6F#, 16#4A7484AA#, 16#5CB0A9DC#, 16#76F988DA#,
      16#983E5152#, 16#A831C66D#, 16#B00327C8#, 16#BF597FC7#,
      16#C6E00BF3#, 16#D5A79147#, 16#06CA6351#, 16#14292967#,
      16#27B70A85#, 16#2E1B2138#, 16#4D2C6DFC#, 16#53380D13#,
      16#650A7354#, 16#766A0ABB#, 16#81C2C92E#, 16#92722C85#,
      16#A2BFE8A1#, 16#A81A664B#, 16#C24B8B70#, 16#C76C51A3#,
      16#D192E819#, 16#D6990624#, 16#F40E3585#, 16#106AA070#,
      16#19A4C116#, 16#1E376C08#, 16#2748774C#, 16#34B0BCB5#,
      16#391C0CB3#, 16#4ED8AA4A#, 16#5B9CCA4F#, 16#682E6FF3#,
      16#748F82EE#, 16#78A5636F#, 16#84C87814#, 16#8CC70208#,
      16#90BEFFFA#, 16#A4506CEB#, 16#BEF9A3F7#, 16#C67178F2#);
   --  Round constants

   SHA256_Init_Constants : constant State_Array :=
     (0 => 16#6A09_E667#,
      1 => 16#BB67_AE85#,
      2 => 16#3C6E_F372#,
      3 => 16#A54F_F53A#,
      4 => 16#510E_527F#,
      5 => 16#9B05_688C#,
      6 => 16#1F83_D9AB#,
      7 => 16#5BE0_CD19#);

   SHA224_Init_Constants : constant State_Array :=
     (0 => 16#C105_9ED8#,
      1 => 16#367C_D507#,
      2 => 16#3070_DD17#,
      3 => 16#F70E_5939#,
      4 => 16#FFC0_0B31#,
      5 => 16#6858_1511#,
      6 => 16#64F9_8FA7#,
      7 => 16#BEFA_4FA4#);

   ------------------------------
   -- SHA-256 round operations --
   ------------------------------

   function S0 (X : Unsigned_32) return Unsigned_32 is
     (Rotate_Right (X, 7)  xor
      Rotate_Right (X, 18) xor
      Shift_Right  (X, 3));

   function S1 (X : Unsigned_32) return Unsigned_32 is
     (Rotate_Right (X, 17) xor
      Rotate_Right (X, 19) xor
      Shift_Right  (X, 10));

   function E0 (A : Unsigned_32) return Unsigned_32 is
     (Rotate_Right (A, 2)  xor
      Rotate_Right (A, 13) xor
      Rotate_Right (A, 22));

   function E1 (E : Unsigned_32) return Unsigned_32 is
     (Rotate_Right (E, 6)  xor
      Rotate_Right (E, 11) xor
      Rotate_Right (E, 25));

   function F0 (A, B, C : Unsigned_32) return Unsigned_32 is
     ((A and B) or (C and (A or B)));

   function F1 (E, F, G : Unsigned_32) return Unsigned_32 is
     (G xor (E and ((F xor G))));

   procedure Transform
     (A, B, C :        Unsigned_32;
      D       : in out Unsigned_32;
      E, F, G :        Unsigned_32;
      H       : in out Unsigned_32;
      W, K    :        Unsigned_32)
   with
     Inline_Always,
     Global  => null,
     Depends => (D => (D, E, F, G, H, K, W),
                 H => (A, B, C, E, F, G, H, K, W));

   function R
     (I : Natural;
      W : Types.U32_Array)
      return Unsigned_32
   with
     Inline,
     Global  => null,
     Pre     => (W'First = 0
                 and then W'Last in 15 .. 63
                 and then I = W'Last + 1);

   ---------------
   -- Transform --
   ---------------

   procedure Transform
     (A, B, C :        Unsigned_32;
      D       : in out Unsigned_32;
      E, F, G :        Unsigned_32;
      H       : in out Unsigned_32;
      W, K    :        Unsigned_32)
   is
      T1 : Unsigned_32;
      T2 : Unsigned_32;

   begin
      T1 := H + E1 (E) + F1 (E, F, G) + K + W;
      T2 := E0 (A) + F0 (A, B, C);

      D := D  + T1;
      H := T1 + T2;
   end Transform;

   -------
   -- R --
   -------

   function R
     (I : Natural;
      W : Types.U32_Array)
      return Unsigned_32
   is
     (S1 (W (I - 2))  + W (I - 7) +
      S0 (W (I - 15)) + W (I - 16));

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx.State := (case Ctx.Algorithm is
                      when SHA256 => SHA256_Init_Constants,
                      when SHA224 => SHA224_Init_Constants);
      Ctx.Bytes_Processed := 0;
      Ctx.Finished        := False;
      Block_Streaming.Initialize (Ctx.Buffer);
   end Initialize;

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
      --  violated then the calculated length is the actual length
      --  modulo 2**64.

      Length_Bits := Ctx.Bytes_Processed * 8;
      To_Bytes_BE (Length_Bits, Ctx.Buffer.Partial_Block (56 .. 63));

      Compress_Blocks (Ctx.State, Ctx.Buffer.Partial_Block);

      --  Output the digest

      pragma Assert_And_Cut (Hash'Length = Hash_Length (Ctx.Algorithm));

      Pos := Hash'First;
      To_Bytes_BE (Ctx.State (0), Hash (Pos      .. Pos +  3));
      To_Bytes_BE (Ctx.State (1), Hash (Pos + 4  .. Pos +  7));
      To_Bytes_BE (Ctx.State (2), Hash (Pos + 8  .. Pos + 11));
      To_Bytes_BE (Ctx.State (3), Hash (Pos + 12 .. Pos + 15));
      To_Bytes_BE (Ctx.State (4), Hash (Pos + 16 .. Pos + 19));
      To_Bytes_BE (Ctx.State (5), Hash (Pos + 20 .. Pos + 23));
      To_Bytes_BE (Ctx.State (6), Hash (Pos + 24 .. Pos + 27));

      if Ctx.Algorithm = SHA256 then
         To_Bytes_BE (Ctx.State (7), Hash (Pos + 28 .. Pos + 31));
      end if;

      Sanitize (Ctx.State);
      Block_Streaming.Sanitize (Ctx.Buffer);

      Ctx.Finished := True;
   end Finish;

   ---------------------
   -- Compress_Blocks --
   ---------------------

   --  There are two implementations of this procedure, one optimized for
   --  speed and another optimized for code size.

   procedure Compress_Blocks
     (State : in out State_Array;
      Blocks :        Byte_Array)
   is separate;

   ------------------
   -- Compute_Hash --
   ------------------

   procedure Compute_Hash
     (Algorithm :     Algorithm_Kind;
      Data      :     Byte_Array;
      Hash      : out Byte_Array)
   is
      Ctx : Context (Algorithm);
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
     (Algorithm     : Algorithm_Kind;
      Data          : Byte_Array;
      Expected_Hash : Byte_Array)
      return Boolean
   is
      HLen : constant Hash_Length_Number := Hash_Length (Algorithm);

      Hash  : Byte_Array (1 .. HLen);
      Valid : Boolean;

   begin
      Compute_Hash (Algorithm, Data, Hash);

      Valid := Equal_Constant_Time
                 (Expected_Hash, Hash (1 .. Expected_Hash'Length));

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Hash);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Hash);

      return Valid;
   end Verify_Hash;

end Tux.SHA256;
