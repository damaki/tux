--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
separate (Tux.Sanitization)
procedure Generic_Sanitize_Array (Target : out Array_Type) is
begin
   Target := (others => Sanitize_Value);

   pragma Inspection_Point (Target);

   Memory_Fence;
end Generic_Sanitize_Array;