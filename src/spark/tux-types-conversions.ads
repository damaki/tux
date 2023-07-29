--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  @summary
--  Utilities to convert data to and from byte arrays
package Tux.Types.Conversions with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   --------------------------------------------
   -- Modular Type to Byte Array Conversions --
   --------------------------------------------

   procedure To_Bytes_LE
     (Value :     Unsigned_32;
      Bytes : out Byte_Array)
   with
     Inline,
     Global  => null,
     Relaxed_Initialization => Bytes,
     Pre     => Bytes'Length = 4,
     Post    => Bytes'Initialized and To_U32_LE (Bytes) = Value;
   --  Convert a Unsigned_32 to a byte array in little endian format
   --
   --  @param Value The 32-bit value to convert to bytes in little endian
   --               format.
   --  @param Bytes Buffer to where the converted bytes are written.

   procedure To_Bytes_LE
     (Value :     Unsigned_64;
      Bytes : out Byte_Array)
   with
     Inline,
     Global  => null,
     Relaxed_Initialization => Bytes,
     Pre     => Bytes'Length = 8,
     Post    => Bytes'Initialized and To_U64_LE (Bytes) = Value;
   --  Convert a Unsigned_64 to a byte array in little endian format
   --
   --  @param Value The 64-bit value to convert to bytes in little endian
   --               format.
   --  @param Bytes Buffer to where the converted bytes are written.

   procedure To_Bytes_BE
     (Value :     Unsigned_32;
      Bytes : out Byte_Array)
   with
     Inline,
     Global  => null,
     Relaxed_Initialization => Bytes,
     Pre     => Bytes'Length = 4,
     Post    => Bytes'Initialized and To_U32_BE (Bytes) = Value;
   --  Convert a Unsigned_32 to a byte array in big endian format
   --
   --  @param Value The 32-bit value to convert to bytes in big endian format.
   --  @param Bytes Buffer to where the converted bytes are written.

   procedure To_Bytes_BE
     (Value :     Unsigned_64;
      Bytes : out Byte_Array)
   with
     Inline,
     Global  => null,
     Relaxed_Initialization => Bytes,
     Pre     => Bytes'Length = 8,
     Post    => Bytes'Initialized and To_U64_BE (Bytes) = Value;
   --  Convert a Unsigned_64 to a byte array in big endian format
   --
   --  @param Value The 64-bit value to convert to bytes in big endian format.
   --  @param Bytes Buffer to where the converted bytes are written.

   --------------------------------------------
   -- Byte Array to Modular Type Conversions --
   --------------------------------------------

   function To_U32_LE (Bytes : Byte_Array) return Unsigned_32 with
     Inline,
     Global => null,
     Pre    => Bytes'Length = 4;
   --  Convert a 4-byte array to a Unsigned_32 in little endian format
   --
   --  @param Bytes The 4-byte array to convert.
   --  @return The converted value.

   function To_U64_LE (Bytes : Byte_Array) return Unsigned_64 with
     Inline,
     Global => null,
     Pre    => Bytes'Length = 8;
   --  Convert an 8-byte array to a Unsigned_64 in little endian format
   --
   --  @param Bytes The 4-byte array to convert.
   --  @return The converted value.

   function To_U32_BE (Bytes : Byte_Array) return Unsigned_32 with
     Inline,
     Global => null,
     Pre    => Bytes'Length = 4;
   --  Convert a 4-byte array to a Unsigned_32 in big endian format
   --
   --  @param Bytes The 4-byte array to convert.
   --  @return The converted value.

   function To_U64_BE (Bytes : Byte_Array) return Unsigned_64 with
     Inline,
     Global => null,
     Pre    => Bytes'Length = 8;
   --  Convert an 8-byte array to a Unsigned_64 in big endian format
   --
   --  @param Bytes The 4-byte array to convert.
   --  @return The converted value.

end Tux.Types.Conversions;
