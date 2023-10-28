--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces; use Interfaces;

with Tux.Types; use Tux.Types;

--  @summary
--  This package implements cryptographic padding rules.
package Tux.Padding with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   -------------
   -- Pad10*1 --
   -------------

   Pad101_Min_Bits : constant := 2;
   --  Minimum number of padding bits required for the pad10*1 padding rule

   procedure Pad101_With_Suffix
     (Buffer      : out Byte_Array;
      Suffix      :     Unsigned_8;
      Suffix_Bits :     Natural)
   with
     Pre => (Buffer'Length > 0
             and then Suffix_Bits <= Unsigned_8'Size - Pad101_Min_Bits
             and then Natural (Suffix) < 2**Suffix_Bits);
   --  Apply the pad10*1 padding rule to a byte array along with any suffix
   --  bits.
   --
   --  This writes the suffix bits, followed by a "1" bit, then zero or more
   --  "0" bits before the final 1 bit.
   --
   --  @param Buffer The buffer to where the suffix and padding are written.
   --                This buffer must have a nonzero length.
   --  @param Suffix The value of the suffix bits to write.
   --  @param Suffix_Bits The number of suffix bits to write. This function
   --                     supports a maximum of 6 padding bits.

end Tux.Padding;