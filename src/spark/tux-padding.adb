--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.Padding with
  SPARK_Mode
is

   ------------------------
   -- Pad101_With_Suffix --
   ------------------------

   procedure Pad101_With_Suffix
     (Buffer      : out Byte_Array;
      Suffix      :     Unsigned_8;
      Suffix_Bits :     Natural)
   is
   begin
      Buffer := (others => 0);
      Buffer (Buffer'First) := Suffix or Shift_Left (1, Suffix_Bits);
      Buffer (Buffer'Last)  := Buffer (Buffer'Last) or 16#80#;
   end Pad101_With_Suffix;

end Tux.Padding;