--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  @summary
--  Utilities for executing common operations in constant time.
package Tux.Constant_Time with
  Pure,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   generic
      type Index is range <>;
      type Element is mod <>;
      type Element_Array is array (Index range <>) of Element;
   function Generic_Equal (A, B : Element_Array) return Boolean with
     Global => null,
     Pre    => A'Length = B'Length,
     Post   => Generic_Equal'Result = (A = B);
   --  Compare two arrays for equality in constant time.
   --
   --  The two arrays must have equal length.
   --
   --  The time taken to check for equality depends only on the length of the
   --  input arrays; the contents of the arrays has no effect on the timing.
   --
   --  @param A The first array to compare.
   --  @param B The second array to compare.
   --  @return True if the arrays are equal, False otherwise.

end Tux.Constant_Time;
