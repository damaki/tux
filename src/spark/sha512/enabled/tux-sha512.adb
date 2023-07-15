--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types.Conversions; use Tux.Types.Conversions;

package body Tux.SHA512 with
  SPARK_Mode
is

   --====================--
   -- Common Definitions --
   --====================--

   -----------------------
   -- SHA-512 Constants --
   -----------------------

   K : constant Types.U64_Array (0 .. 79) :=
     (16#428A2F98_D728AE22#, 16#71374491_23EF65CD#,
      16#B5C0FBCF_EC4D3B2F#, 16#E9B5DBA5_8189DBBC#,
      16#3956C25B_F348B538#, 16#59F111F1_B605D019#,
      16#923F82A4_AF194F9B#, 16#AB1C5ED5_DA6D8118#,
      16#D807AA98_A3030242#, 16#12835B01_45706FBE#,
      16#243185BE_4EE4B28C#, 16#550C7DC3_D5FFB4E2#,
      16#72BE5D74_F27B896F#, 16#80DEB1FE_3B1696B1#,
      16#9BDC06A7_25C71235#, 16#C19BF174_CF692694#,
      16#E49B69C1_9EF14AD2#, 16#EFBE4786_384F25E3#,
      16#0FC19DC6_8B8CD5B5#, 16#240CA1CC_77AC9C65#,
      16#2DE92C6F_592B0275#, 16#4A7484AA_6EA6E483#,
      16#5CB0A9DC_BD41FBD4#, 16#76F988DA_831153B5#,
      16#983E5152_EE66DFAB#, 16#A831C66D_2DB43210#,
      16#B00327C8_98FB213F#, 16#BF597FC7_BEEF0EE4#,
      16#C6E00BF3_3DA88FC2#, 16#D5A79147_930AA725#,
      16#06CA6351_E003826F#, 16#14292967_0A0E6E70#,
      16#27B70A85_46D22FFC#, 16#2E1B2138_5C26C926#,
      16#4D2C6DFC_5AC42AED#, 16#53380D13_9D95B3DF#,
      16#650A7354_8BAF63DE#, 16#766A0ABB_3C77B2A8#,
      16#81C2C92E_47EDAEE6#, 16#92722C85_1482353B#,
      16#A2BFE8A1_4CF10364#, 16#A81A664B_BC423001#,
      16#C24B8B70_D0F89791#, 16#C76C51A3_0654BE30#,
      16#D192E819_D6EF5218#, 16#D6990624_5565A910#,
      16#F40E3585_5771202A#, 16#106AA070_32BBD1B8#,
      16#19A4C116_B8D2D0C8#, 16#1E376C08_5141AB53#,
      16#2748774C_DF8EEB99#, 16#34B0BCB5_E19B48A8#,
      16#391C0CB3_C5C95A63#, 16#4ED8AA4A_E3418ACB#,
      16#5B9CCA4F_7763E373#, 16#682E6FF3_D6B2B8A3#,
      16#748F82EE_5DEFB2FC#, 16#78A5636F_43172F60#,
      16#84C87814_A1F0AB72#, 16#8CC70208_1A6439EC#,
      16#90BEFFFA_23631E28#, 16#A4506CEB_DE82BDE9#,
      16#BEF9A3F7_B2C67915#, 16#C67178F2_E372532B#,
      16#CA273ECE_EA26619C#, 16#D186B8C7_21C0C207#,
      16#EADA7DD6_CDE0EB1E#, 16#F57D4F7F_EE6ED178#,
      16#06F067AA_72176FBA#, 16#0A637DC5_A2C898A6#,
      16#113F9804_BEF90DAE#, 16#1B710B35_131C471B#,
      16#28DB77F5_23047D84#, 16#32CAAB7B_40C72493#,
      16#3C9EBE0A_15C9BEBC#, 16#431D67C4_9C100D4C#,
      16#4CC5D4BE_CB3E42B6#, 16#597F299C_FC657E2A#,
      16#5FCB6FAB_3AD6FAEC#, 16#6C44198C_4A475817#);

   SHA512_Init_Constants : constant State_Array :=
     (0 => 16#6A09E667_F3BCC908#,
      1 => 16#BB67AE85_84CAA73B#,
      2 => 16#3C6EF372_FE94F82B#,
      3 => 16#A54FF53A_5F1D36F1#,
      4 => 16#510E527F_ADE682D1#,
      5 => 16#9B05688C_2B3E6C1F#,
      6 => 16#1F83D9AB_FB41BD6B#,
      7 => 16#5BE0CD19_137E2179#);

   SHA384_Init_Constants : constant State_Array :=
     (0 => 16#CBBB9D5D_C1059ED8#,
      1 => 16#629A292A_367CD507#,
      2 => 16#9159015A_3070DD17#,
      3 => 16#152FECD8_F70E5939#,
      4 => 16#67332667_FFC00B31#,
      5 => 16#8EB44A87_68581511#,
      6 => 16#DB0C2E0D_64F98FA7#,
      7 => 16#47B5481D_BEFA4FA4#);

   SHA512_256_Init_Constants : constant State_Array :=
     (0 => 16#22312194_FC2BF72C#,
      1 => 16#9F555FA3_C84C64C2#,
      2 => 16#2393B86B_6F53B151#,
      3 => 16#96387719_5940EABD#,
      4 => 16#96283EE2_A88EFFE3#,
      5 => 16#BE5E1E25_53863992#,
      6 => 16#2B0199FC_2C85B8AA#,
      7 => 16#0EB72DDC_81C52CA2#);

   SHA512_224_Init_Constants : constant State_Array :=
     (0 => 16#8C3D37C8_19544DA2#,
      1 => 16#73E19966_89DCD4D6#,
      2 => 16#1DFAB7AE_32FF9C82#,
      3 => 16#679DD514_582F9FCF#,
      4 => 16#0F6D2B69_7BD44DA8#,
      5 => 16#77E36F73_04C48942#,
      6 => 16#3F9D85A8_6A1D36C8#,
      7 => 16#1112E6AD_91D692A1#);

   ------------------------------
   -- SHA-512 round operations --
   ------------------------------

   function S0 (X : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (X, 1) xor
      Rotate_Right (X, 8) xor
      Shift_Right  (X, 7));

   function S1 (X : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (X, 19) xor
      Rotate_Right (X, 61) xor
      Shift_Right  (X, 6));

   function E0 (A : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (A, 28) xor
      Rotate_Right (A, 34) xor
      Rotate_Right (A, 39));

   function E1 (E : Unsigned_64) return Unsigned_64 is
     (Rotate_Right (E, 14) xor
      Rotate_Right (E, 18) xor
      Rotate_Right (E, 41));

   function F0 (A, B, C : Unsigned_64) return Unsigned_64 is
     ((A and B) or (C and (A or B)));

   function F1 (E, F, G : Unsigned_64) return Unsigned_64 is
     (G xor (E and ((F xor G))));

   procedure Transform
     (A, B, C :        Unsigned_64;
      D       : in out Unsigned_64;
      E, F, G :        Unsigned_64;
      H       : in out Unsigned_64;
      W, K    :        Unsigned_64)
   with
     Inline_Always,
     Global  => null,
     Depends => (D => (D, E, F, G, H, K, W),
                 H => (A, B, C, E, F, G, H, K, W));

   function R
     (I : Natural;
      W : Types.U64_Array) return Unsigned_64
   with
     Inline,
     Global  => null,
     Pre     => (W'First = 0
                 and then W'Last in 15 .. 79
                 and then I = W'Last + 1);

   ---------------
   -- Transform --
   ---------------

   procedure Transform
     (A, B, C :        Unsigned_64;
      D       : in out Unsigned_64;
      E, F, G :        Unsigned_64;
      H       : in out Unsigned_64;
      W, K    :        Unsigned_64)
   is
      T1 : Unsigned_64;
      T2 : Unsigned_64;

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
      W : Types.U64_Array) return Unsigned_64
   is
     (S1 (W (I - 2))  + W (I - 7) +
      S0 (W (I - 15)) + W (I - 16));

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx.State := (case Ctx.Algorithm is
                      when SHA512     => SHA512_Init_Constants,
                      when SHA384     => SHA384_Init_Constants,
                      when SHA512_256 => SHA512_256_Init_Constants,
                      when SHA512_224 => SHA512_224_Init_Constants);
      Ctx.Byte_Length_Low  := 0;
      Ctx.Byte_Length_High := 0;
      Ctx.Finished         := False;
      Block_Streaming.Initialize (Ctx.Buffer);
   end Initialize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
      Temp : Unsigned_64;

   begin
      Block_Streaming.Update (Ctx.Buffer, Data, Ctx.State);

      --  Update the message length (128-bit number)

      Temp := Ctx.Byte_Length_Low;
      Ctx.Byte_Length_Low := Ctx.Byte_Length_Low + Unsigned_64 (Data'Length);

      if Ctx.Byte_Length_Low < Temp then
         Ctx.Byte_Length_High := Ctx.Byte_Length_High + 1;
      end if;
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

      High : Unsigned_64;
      Low  : Unsigned_64;

   begin
      --  Add padding bytes. 16#80# followed by zeroes then the last 16 bytes
      --  for the message length in bits.

      Length := Ctx.Buffer.Partial_Block_Length;

      Ctx.Buffer.Partial_Block (Length) := 16#80#;
      Ctx.Buffer.Partial_Block (Length + 1 .. 111) := (others => 0);

      Length := Length + 1;

      if Length > 112 then
         --  Not enough space remaining for the length
         Ctx.Buffer.Partial_Block (Length .. 127) := (others => 0);
         Compress_Blocks (Ctx.State, Ctx.Buffer.Partial_Block);
         Ctx.Buffer.Partial_Block (0 .. 111)      := (others => 0);
      end if;

      --  Multiply length by 8 (byte count => bit count)
      --
      --  We assume here that the total message length does not exceed
      --  2**128 - 1 bits.

      High := Shift_Right (Ctx.Byte_Length_Low,  61) or
              Shift_Left  (Ctx.Byte_Length_High, 3);
      Low  := Shift_Left  (Ctx.Byte_Length_Low,  3);

      --  Add the length

      To_Bytes_BE (High, Ctx.Buffer.Partial_Block (112 .. 119));
      To_Bytes_BE (Low,  Ctx.Buffer.Partial_Block (120 .. 127));

      Compress_Blocks (Ctx.State, Ctx.Buffer.Partial_Block);

      --  Output the digest

      pragma Assert_And_Cut (Hash'Length = Hash_Length (Ctx.Algorithm));

      Pos := Hash'First;
      To_Bytes_BE (Ctx.State (0), Hash (Pos      .. Pos +  7));
      To_Bytes_BE (Ctx.State (1), Hash (Pos + 8  .. Pos + 15));
      To_Bytes_BE (Ctx.State (2), Hash (Pos + 16 .. Pos + 23));

      if Ctx.Algorithm = SHA512_224 then
         To_Bytes_BE (Unsigned_32 (Shift_Right (Ctx.State (3), 32)),
                      Hash (Pos + 24 .. Pos + 27));

      else
         To_Bytes_BE (Ctx.State (3), Hash (Pos + 24 .. Pos + 31));

         if Ctx.Algorithm in SHA512 | SHA384 then
            To_Bytes_BE (Ctx.State (4), Hash (Pos + 32 .. Pos + 39));
            To_Bytes_BE (Ctx.State (5), Hash (Pos + 40 .. Pos + 47));

            if Ctx.Algorithm = SHA512 then
               To_Bytes_BE (Ctx.State (6), Hash (Pos + 48 .. Pos + 55));
               To_Bytes_BE (Ctx.State (7), Hash (Pos + 56 .. Pos + 63));
            end if;
         end if;
      end if;

      Sanitize (Ctx.State);
      Sanitize (Ctx.Buffer.Partial_Block);

      Ctx.Finished := True;
   end Finish;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      Sanitize (Ctx.State);
      Ctx.Byte_Length_Low  := 0;
      Ctx.Byte_Length_High := 0;
      Ctx.Finished         := True;
      Block_Streaming.Sanitize (Ctx.Buffer);
   end Sanitize;

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
      HLen  : constant Hash_Length_Number := Hash_Length (Algorithm);
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

end Tux.SHA512;
