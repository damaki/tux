--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces;

package body Tux.SHAKE with
  SPARK_Mode
is

   --  SHA-3 appends a four-bit suffix to each message

   SHAKE_Suffix      : constant Interfaces.Unsigned_8 := 2#1111#;
   SHAKE_Suffix_Bits : constant Suffix_Bit_Count      := 4;

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHAKE128 =>
            Sponge_Keccak_1600_24.Initialize (Ctx.Ctx_128);
         when SHAKE256 =>
            Sponge_Keccak_1600_24.Initialize (Ctx.Ctx_256);
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
         when SHAKE128 =>
            Sponge_Keccak_1600_24.Absorb (Ctx.Ctx_128, Data);
         when SHAKE256 =>
            Sponge_Keccak_1600_24.Absorb (Ctx.Ctx_256, Data);
      end case;
   end Update;

   -------------
   -- Extract --
   -------------

   procedure Extract
     (Ctx    : in out Context;
      Output :    out Byte_Array)
   is
   begin
      if Current_State (Ctx) = Updating then
         case Ctx.Algorithm is
            when SHAKE128 =>
               Sponge_Keccak_1600_24.Prepare_Squeeze
                 (Ctx.Ctx_128, SHAKE_Suffix, SHAKE_Suffix_Bits);

            when SHAKE256 =>
               Sponge_Keccak_1600_24.Prepare_Squeeze
                 (Ctx.Ctx_256, SHAKE_Suffix, SHAKE_Suffix_Bits);
         end case;
      end if;

      case Ctx.Algorithm is
         when SHAKE128 =>
            Sponge_Keccak_1600_24.Squeeze (Ctx.Ctx_128, Output);
         when SHAKE256 =>
            Sponge_Keccak_1600_24.Squeeze (Ctx.Ctx_256, Output);
      end case;
   end Extract;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHAKE128 =>
            Sponge_Keccak_1600_24.Sanitize (Ctx.Ctx_128);
         when SHAKE256 =>
            Sponge_Keccak_1600_24.Sanitize (Ctx.Ctx_256);
      end case;
   end Sanitize;

end Tux.SHAKE;