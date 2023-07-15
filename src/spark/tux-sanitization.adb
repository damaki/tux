--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

package body Tux.Sanitization with
  SPARK_Mode
is

   ----------------------------
   -- Generic_Sanitize_Array --
   ----------------------------

   procedure Generic_Sanitize_Array (Target : out Array_Type) is separate;

   ----------------------
   -- Generic_Sanitize --
   ----------------------

   procedure Generic_Sanitize (Target : out Element_Type) is separate;

end Tux.Sanitization;
