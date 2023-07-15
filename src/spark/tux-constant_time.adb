--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  Postconditions are disabled to prevent potential timing leaks when the
--  library is built with assertions enabled.

pragma Assertion_Policy (Post => Ignore);

package body Tux.Constant_Time with
  SPARK_Mode
is

   -------------------
   -- Generic_Equal --
   -------------------

   function Generic_Equal (A, B : Element_Array) return Boolean is

      --  Disable Loop_Invariant checks at runtime to avoid the possibility
      --  of timing leaks when assertions are enabled.

      pragma Assertion_Policy (Loop_Invariant => Ignore);

      Diff : Element := 0;

   begin
      for I in Index range 0 .. A'Length - 1 loop
         pragma Loop_Invariant
           ((Diff = 0)
            =
            (A (A'First .. A'First + I - 1) = B (B'First .. B'First + I - 1)));

         Diff := Diff or (A (A'First + I) xor B (B'First + I));
      end loop;

      return Diff = 0;
   end Generic_Equal;

end Tux.Constant_Time;
