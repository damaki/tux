--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.Generic_Sponge is

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx.Length := 0;
      Ctx.State  := Absorbing;
      Ctx.Buffer := (others => 0);
      Initialize (Ctx.Internal_State);
   end Initialize;

   ------------
   -- Absorb --
   ------------

   procedure Absorb
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
      Offset    : Byte_Count := 0;
      Remaining : Byte_Count := Data'Length;

      Bytes_To_Copy : Byte_Count;
      Pos           : Index_Number;
   begin
      --  Append the data to any leftovers from previous calls until we get a
      --  complete block.

      if Ctx.Length > 0 then
         Bytes_To_Copy :=
           Byte_Count'Min (Remaining, Ctx.Buffer'Length - Ctx.Length);

         Ctx.Buffer (Ctx.Length + 1 .. Ctx.Length + Bytes_To_Copy) :=
           Data (Data'First .. Data'First + Bytes_To_Copy - 1);

         Offset     := Offset     + Bytes_To_Copy;
         Remaining  := Remaining  - Bytes_To_Copy;
         Ctx.Length := Ctx.Length + Bytes_To_Copy;

         if Ctx.Length = Ctx.Rate then
            Ctx.Length := 0;

            XOR_Bytes_Into_Context (Ctx.Internal_State, Ctx.Buffer);
            Permute (Ctx.Internal_State);
         end if;
      end if;

      --  Process full blocks

      while Remaining >= Ctx.Rate loop
         pragma Loop_Variant (Decreases => Remaining);
         pragma Loop_Invariant (Offset + Remaining = Data'Length);
         pragma Loop_Invariant (Ctx.Length = 0);

         Pos := Data'First + Offset;
         XOR_Bytes_Into_Context
           (Ctx.Internal_State, Data (Pos .. Pos + Ctx.Rate - 1));

         Permute (Ctx.Internal_State);

         Offset    := Offset    + Ctx.Rate;
         Remaining := Remaining - Ctx.Rate;
      end loop;

      --  Store any leftovers in a partial block

      if Remaining > 0 then
         pragma Assert (Ctx.Length = 0);

         Pos := Data'First + Offset;
         Ctx.Buffer (1 .. Remaining) := Data (Pos .. Data'Last);
         Ctx.Length := Remaining;
      end if;
   end Absorb;

   ---------------------
   -- Prepare_Squeeze --
   ---------------------

   procedure Prepare_Squeeze
     (Ctx         : in out Context;
      Suffix      :        Unsigned_8;
      Suffix_Bits :        Suffix_Bit_Count)
   is
   begin
      Pad_With_Suffix
        (Buffer      => Ctx.Buffer (Ctx.Length + 1 .. Ctx.Buffer'Last),
         Suffix      => Suffix,
         Suffix_Bits => Suffix_Bits);

      XOR_Bytes_Into_Context (Ctx.Internal_State, Ctx.Buffer);

      Ctx.Length := Ctx.Rate;
      Ctx.State  := Squeezing;
   end Prepare_Squeeze;

   -------------
   -- Squeeze --
   -------------

   procedure Squeeze
     (Ctx  : in out Context;
      Data :    out Byte_Array)
   is
      Offset    : Byte_Count := 0;
      Remaining : Byte_Count := Data'Length;

      Bytes_To_Copy : Byte_Count;
      Pos           : Index_Number;

   begin
      --  Read any leftovers/unused bytes from a previous block

      if Ctx.Length < Ctx.Rate then
         Bytes_To_Copy :=
           Byte_Count'Min (Remaining, Ctx.Rate - Ctx.Length);

         Data (Data'First .. Data'First + Bytes_To_Copy - 1) :=
           Ctx.Buffer (Ctx.Length + 1 .. Ctx.Length + Bytes_To_Copy);

         Ctx.Length := Ctx.Length + Bytes_To_Copy;
         Offset     := Offset     + Bytes_To_Copy;
         Remaining  := Remaining  - Bytes_To_Copy;
      end if;

      --  Process full blocks

      while Remaining >= Ctx.Rate loop
         pragma Loop_Variant (Decreases => Remaining);
         pragma Loop_Invariant (Offset + Remaining = Data'Length);
         pragma Loop_Invariant (Ctx.Length = Ctx.Rate);
         pragma Loop_Invariant
           (Data (Data'First .. Data'First + Offset - 1)'Initialized);

         Permute (Ctx.Internal_State);

         Pos := Data'First + Offset;
         Extract_Bytes (Ctx.Internal_State, Data (Pos .. Pos + Ctx.Rate - 1));

         Offset    := Offset    + Ctx.Rate;
         Remaining := Remaining - Ctx.Rate;
      end loop;

      --  Handle the last partial block and store any leftovers for subsequent
      --  calls.

      if Remaining > 0 then
         pragma Assert (Ctx.Length = Ctx.Rate);

         Permute (Ctx.Internal_State);
         Extract_Bytes (Ctx.Internal_State, Ctx.Buffer);

         Pos := Data'First + Offset;
         Data (Pos .. Data'Last) := Ctx.Buffer (1 .. Remaining);
         Ctx.Length := Remaining;
      end if;
   end Squeeze;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      Ctx.Length     := Ctx.Rate;
      Ctx.State      := Squeezing;
      Sanitize (Ctx.Internal_State);
      Sanitize (Ctx.Buffer);
   end Sanitize;

end Tux.Generic_Sponge;