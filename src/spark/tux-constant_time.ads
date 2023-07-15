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
   --  The time taken to check for equality depends only on the length of the
   --  input arrays; the contents of the arrays has no effect on the timing.

end Tux.Constant_Time;
