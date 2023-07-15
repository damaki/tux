--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.Generic_Block_Streaming is

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      Ctx.Partial_Block_Length := 0;
      Sanitize (Ctx.Partial_Block);
   end Sanitize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx   : in out Context;
      Data  :        Byte_Array;
      State : in out Internal_State_Type)
   is
      Remaining : Natural;
      Offset    : Natural;

      Bytes_To_Copy      : Byte_Count;
      Length             : Byte_Count;
      Pos                : Natural;
      Full_Blocks_Length : Byte_Count;

   begin
      Length := Ctx.Partial_Block_Length;

      --  Append data with any leftovers from the previous partial block

      if Length > 0 then
         Bytes_To_Copy := Natural'Min (Data'Length, Block_Length - Length);

         Ctx.Partial_Block (Length .. Length + Bytes_To_Copy - 1) :=
           Data (Data'First .. Data'First + Bytes_To_Copy - 1);

         Length := Length + Bytes_To_Copy;

         --  Process a complete block if we have it

         if Length = Block_Length then
            Process_Blocks (State, Ctx.Partial_Block);
            Length := 0;
         end if;

         Ctx.Partial_Block_Length := Length;

         Offset    := Bytes_To_Copy;
         Remaining := Data'Length - Bytes_To_Copy;

      else
         Offset    := 0;
         Remaining := Data'Length;
      end if;

      pragma Assert (if Remaining > 0 then Ctx.Partial_Block_Length = 0);
      pragma Assert (Offset + Remaining = Data'Length);

      --  Process complete blocks

      if Remaining >= Block_Length then
         Full_Blocks_Length := Remaining - (Remaining mod Block_Length);

         Pos := Data'First + Offset;

         Process_Blocks (State, Data (Pos .. Pos + Full_Blocks_Length - 1));

         Offset    := Offset    + Full_Blocks_Length;
         Remaining := Remaining - Full_Blocks_Length;
      end if;

      --  Store any leftovers

      if Remaining > 0 then
         Pos := Data'First + Offset;

         Ctx.Partial_Block (0 .. Remaining - 1) := Data (Pos .. Data'Last);

         Ctx.Partial_Block_Length := Remaining;
      end if;
   end Update;

end Tux.Generic_Block_Streaming;
