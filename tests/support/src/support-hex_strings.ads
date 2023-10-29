--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces;    use Interfaces;
with Tux.Types;

package Support.Hex_Strings is

   function Valid_Hex_String (Str : String) return Boolean is
     (Str'Length mod 2 = 0
      and (for all C of Str => C in '0' .. '9' | 'a' .. 'f' | 'A' .. 'F'));
   --  Check if a string is a valid hexadecimal string

   procedure Print_Hex_String (Data : Tux.Types.Byte_Array);
   --  Print a byte array as a hexadecimal string to the standard output

   procedure Parse_Hex_String
     (Str  :     String;
      Data : out Tux.Types.Byte_Array)
   with
     Pre => (Str'Length mod 2 = 0
             and then Data'Length = Str'Length / 2);
   --  Parse a hexadecimal string into a byte array.
   --
   --  The input string can contain both upper-case and lower-case hexadecimal
   --  digits.

   function From_Hex_Nibble (C : Character) return Unsigned_8 is
     (case C is
         when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
         when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
         when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
         when others =>
            raise Constraint_Error with
              ''' & C & "' is not a valid hexadecimal digit");

end Support.Hex_Strings;
