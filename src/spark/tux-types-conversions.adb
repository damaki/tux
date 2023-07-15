--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.Types.Conversions with
  SPARK_Mode
is

   -----------------
   -- To_Bytes_LE --
   -----------------

   procedure To_Bytes_LE
     (Value :     Unsigned_32;
      Bytes : out Byte_Array)
   is
      I : constant Integer := Bytes'First;
   begin
      Bytes (I)     := Unsigned_8 (Value and 16#FF#);
      Bytes (I + 1) := Unsigned_8 (Shift_Right (Value, 8)  and 16#FF#);
      Bytes (I + 2) := Unsigned_8 (Shift_Right (Value, 16) and 16#FF#);
      Bytes (I + 3) := Unsigned_8 (Shift_Right (Value, 24));
   end To_Bytes_LE;

   -----------------
   -- To_Bytes_LE --
   -----------------

   procedure To_Bytes_LE
     (Value :     Unsigned_64;
      Bytes : out Byte_Array)
   is
      I : constant Integer := Bytes'First;
   begin
      Bytes (I)     := Unsigned_8 (Value and 16#FF#);
      Bytes (I + 1) := Unsigned_8 (Shift_Right (Value, 8)  and 16#FF#);
      Bytes (I + 2) := Unsigned_8 (Shift_Right (Value, 16) and 16#FF#);
      Bytes (I + 3) := Unsigned_8 (Shift_Right (Value, 24) and 16#FF#);
      Bytes (I + 4) := Unsigned_8 (Shift_Right (Value, 32) and 16#FF#);
      Bytes (I + 5) := Unsigned_8 (Shift_Right (Value, 40) and 16#FF#);
      Bytes (I + 6) := Unsigned_8 (Shift_Right (Value, 48) and 16#FF#);
      Bytes (I + 7) := Unsigned_8 (Shift_Right (Value, 56));
   end To_Bytes_LE;

   -----------------
   -- To_Bytes_BE --
   -----------------

   procedure To_Bytes_BE
     (Value :     Unsigned_32;
      Bytes : out Byte_Array)
   is
      I : constant Integer := Bytes'First;
   begin
      Bytes (I)     := Unsigned_8 (Shift_Right (Value, 24));
      Bytes (I + 1) := Unsigned_8 (Shift_Right (Value, 16) and 16#FF#);
      Bytes (I + 2) := Unsigned_8 (Shift_Right (Value, 8)  and 16#FF#);
      Bytes (I + 3) := Unsigned_8 (Value and 16#FF#);
   end To_Bytes_BE;

   -----------------
   -- To_Bytes_BE --
   -----------------

   procedure To_Bytes_BE
     (Value :     Unsigned_64;
      Bytes : out Byte_Array)
   is
      I : constant Integer := Bytes'First;
   begin
      Bytes (I)     := Unsigned_8 (Shift_Right (Value, 56));
      Bytes (I + 1) := Unsigned_8 (Shift_Right (Value, 48) and 16#FF#);
      Bytes (I + 2) := Unsigned_8 (Shift_Right (Value, 40) and 16#FF#);
      Bytes (I + 3) := Unsigned_8 (Shift_Right (Value, 32) and 16#FF#);
      Bytes (I + 4) := Unsigned_8 (Shift_Right (Value, 24) and 16#FF#);
      Bytes (I + 5) := Unsigned_8 (Shift_Right (Value, 16) and 16#FF#);
      Bytes (I + 6) := Unsigned_8 (Shift_Right (Value, 8)  and 16#FF#);
      Bytes (I + 7) := Unsigned_8 (Value and 16#FF#);
   end To_Bytes_BE;

   ---------------
   -- To_U32_LE --
   ---------------

   function To_U32_LE (Bytes : Byte_Array) return Unsigned_32 is
     (Unsigned_32 (Bytes (Bytes'First)) or
      Shift_Left (Unsigned_32 (Bytes (Bytes'First + 1)), 8) or
      Shift_Left (Unsigned_32 (Bytes (Bytes'First + 2)), 16) or
      Shift_Left (Unsigned_32 (Bytes (Bytes'First + 3)), 24));

   ---------------
   -- To_U64_LE --
   ---------------

   function To_U64_LE (Bytes : Byte_Array) return Unsigned_64 is
     (Unsigned_64 (Bytes (Bytes'First)) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 1)), 8) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 2)), 16) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 3)), 24) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 4)), 32) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 5)), 40) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 6)), 48) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 7)), 56));

   ---------------
   -- To_U32_BE --
   ---------------

   function To_U32_BE (Bytes : Byte_Array) return Unsigned_32 is
     (Unsigned_32 (Bytes (Bytes'First + 3)) or
      Shift_Left (Unsigned_32 (Bytes (Bytes'First + 2)), 8) or
      Shift_Left (Unsigned_32 (Bytes (Bytes'First + 1)), 16) or
      Shift_Left (Unsigned_32 (Bytes (Bytes'First)),     24));

   ---------------
   -- To_U64_BE --
   ---------------

   function To_U64_BE (Bytes : Byte_Array) return Unsigned_64 is
     (Unsigned_64 (Bytes (Bytes'First + 7)) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 6)), 8) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 5)), 16) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 4)), 24) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 3)), 32) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 2)), 40) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First + 1)), 48) or
      Shift_Left (Unsigned_64 (Bytes (Bytes'First)),     56));

end Tux.Types.Conversions;
