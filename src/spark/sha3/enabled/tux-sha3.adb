--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces;

package body Tux.SHA3 with
  SPARK_Mode
is

   --  SHA-3 appends a two-bit suffix to each message

   SHA3_Suffix      : constant Interfaces.Unsigned_8                  := 2#10#;
   SHA3_Suffix_Bits : constant Sponge_Keccak_1600_24.Suffix_Bit_Count := 2;

   procedure Generate_Hash
     (Ctx  : in out Sponge_Keccak_1600_24.Context;
      Hash :    out Byte_Array)
   with
     Relaxed_Initialization => Hash,
     Pre  => Current_State (Ctx) = Absorbing,
     Post => Current_State (Ctx) = Squeezing and Hash'Initialized;
   --  Absorb the SHA-3 suffix bits then squeeze the hash from the sponge

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHA3_224 =>
            Sponge_Keccak_1600_24.Initialize (Ctx.Ctx_224);
         when SHA3_256 =>
            Sponge_Keccak_1600_24.Initialize (Ctx.Ctx_256);
         when SHA3_384 =>
            Sponge_Keccak_1600_24.Initialize (Ctx.Ctx_384);
         when SHA3_512 =>
            Sponge_Keccak_1600_24.Initialize (Ctx.Ctx_512);
      end case;
   end Initialize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
   begin
      case Ctx.Algorithm is
         when SHA3_224 =>
            Sponge_Keccak_1600_24.Absorb (Ctx.Ctx_224, Data);
         when SHA3_256 =>
            Sponge_Keccak_1600_24.Absorb (Ctx.Ctx_256, Data);
         when SHA3_384 =>
            Sponge_Keccak_1600_24.Absorb (Ctx.Ctx_384, Data);
         when SHA3_512 =>
            Sponge_Keccak_1600_24.Absorb (Ctx.Ctx_512, Data);
      end case;
   end Update;

   ------------
   -- Finish --
   ------------

   procedure Finish
     (Ctx  : in out Context;
      Hash :    out Byte_Array)
   is
   begin
      case Ctx.Algorithm is
         when SHA3_224 =>
            Generate_Hash (Ctx.Ctx_224, Hash);
         when SHA3_256 =>
            Generate_Hash (Ctx.Ctx_256, Hash);
         when SHA3_384 =>
            Generate_Hash (Ctx.Ctx_384, Hash);
         when SHA3_512 =>
            Generate_Hash (Ctx.Ctx_512, Hash);
      end case;
   end Finish;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHA3_224 =>
            Sponge_Keccak_1600_24.Sanitize (Ctx.Ctx_224);
         when SHA3_256 =>
            Sponge_Keccak_1600_24.Sanitize (Ctx.Ctx_256);
         when SHA3_384 =>
            Sponge_Keccak_1600_24.Sanitize (Ctx.Ctx_384);
         when SHA3_512 =>
            Sponge_Keccak_1600_24.Sanitize (Ctx.Ctx_512);
      end case;
   end Sanitize;

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

   -------------------
   -- Generate_Hash --
   -------------------

   procedure Generate_Hash
     (Ctx  : in out Sponge_Keccak_1600_24.Context;
      Hash :    out Byte_Array)
   is
   begin
      Prepare_Squeeze (Ctx, SHA3_Suffix, SHA3_Suffix_Bits);
      Squeeze (Ctx, Hash);
   end Generate_Hash;

end Tux.SHA3;
