--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces; use Interfaces;

with Tux.Constant_Time;
with Tux.Sanitization;

package Tux.Types with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   ------------------------
   --  Type Declarations --
   ------------------------

   subtype Byte_Count is Natural;
   --  Represents a quantity of bytes

   subtype Index_Number is Byte_Count range 0 .. Natural'Last - 1;

   type Byte_Array is array (Index_Number range <>) of Unsigned_8;
   type U32_Array  is array (Index_Number range <>) of Unsigned_32;
   type U64_Array  is array (Index_Number range <>) of Unsigned_64;

   Empty_Byte_Array : constant Byte_Array (1 .. 0) := (others => 0);

   ----------------------------
   -- Sanitation Operations  --
   ----------------------------

   --  These subprograms securely sanitize the contents of arrays in a way
   --  that prevents the compiler from optimizing away the writes.

   procedure Sanitize is new Tux.Sanitization.Generic_Sanitize_Array
     (Index_Type     => Index_Number,
      Element_Type   => Unsigned_8,
      Sanitize_Value => 0,
      Array_Type     => Byte_Array);

   procedure Sanitize is new Tux.Sanitization.Generic_Sanitize_Array
     (Index_Type     => Index_Number,
      Element_Type   => Unsigned_32,
      Sanitize_Value => 0,
      Array_Type     => U32_Array);

   procedure Sanitize is new Tux.Sanitization.Generic_Sanitize_Array
     (Index_Type     => Index_Number,
      Element_Type   => Unsigned_64,
      Sanitize_Value => 0,
      Array_Type     => U64_Array);

   -------------------------------
   -- Constant Time Comparisons --
   -------------------------------

   function Equal_Constant_Time is new Constant_Time.Generic_Equal
     (Index         => Index_Number,
      Element       => Unsigned_8,
      Element_Array => Byte_Array);
   --  Compare two Byte_Arrays for equality in constant time

   function Equal_Constant_Time is new Constant_Time.Generic_Equal
     (Index         => Index_Number,
      Element       => Unsigned_32,
      Element_Array => U32_Array);
   --  Compare two U32_Arrays for equality in constant time

   function Equal_Constant_Time is new Constant_Time.Generic_Equal
     (Index         => Index_Number,
      Element       => Unsigned_64,
      Element_Array => U64_Array);
   --  Compare two U64_Arrays for equality in constant time

end Tux.Types;
