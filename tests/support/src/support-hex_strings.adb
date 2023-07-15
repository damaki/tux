--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Ada.Text_IO; use Ada.Text_IO;

package body Support.Hex_Strings is

   Buffer_Length : constant := 64 * 1024;

   subtype Length_Number is Natural range 0 .. Buffer_Length;

   Hex_Chars : constant array (Unsigned_8 range 0 .. 15) of Character :=
     ('0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');

   ------------------------
   --  Print_Hex_String  --
   ------------------------

   procedure Print_Hex_String (Data : Tux.Types.Byte_Array)
   is
      Buffer : String (1 .. Buffer_Length);
      Len    : Length_Number;

      Remaining : Natural := Data'Length;
      Offset    : Natural := 0;
      Pos       : Natural;

   begin

      while Remaining >= Buffer_Length / 2 loop
         for I in 0 .. (Buffer_Length / 2) - 1 loop
            Pos := Data'First + Offset + I;
            Buffer ((I * 2) + 1) := Hex_Chars (Shift_Right (Data (Pos), 4));
            Buffer ((I * 2) + 2) := Hex_Chars (Data (Pos) and 16#0F#);
         end loop;

         Put (Buffer);

         Remaining := Remaining - (Buffer_Length / 2);
         Offset    := Offset    + (Buffer_Length / 2);
      end loop;

      Len := 0;
      while Remaining > 0 loop
         Pos := Data'First + Offset;
         Buffer (Len + 1) := Hex_Chars (Shift_Right (Data (Pos), 4));
         Buffer (Len + 2) := Hex_Chars (Data (Pos) and 16#0F#);

         Len       := Len       + 2;
         Offset    := Offset    + 1;
         Remaining := Remaining - 1;
      end loop;

      if Len > 0 then
         Put (Buffer (1 .. Len));
      end if;

   end Print_Hex_String;

   ------------------------
   --  Parse_Hex_String  --
   ------------------------

   procedure Parse_Hex_String
     (Str  :     String;
      Data : out Tux.Types.Byte_Array)
   is
      Str_Pos  : Positive := Str'First;
      Data_Pos : Tux.Types.Index_Number := Data'First;

      Upper : Unsigned_8;
      Lower : Unsigned_8;

   begin
      while Str_Pos < Str'Last loop
         Upper := From_Hex_Nibble (Str (Str_Pos));
         Lower := From_Hex_Nibble (Str (Str_Pos + 1));

         Data (Data_Pos) := Shift_Left (Upper, 4) or Lower;

         Data_Pos := Data_Pos + 1;
         Str_Pos  := Str_Pos  + 2;
      end loop;
   end Parse_Hex_String;

end Support.Hex_Strings;
