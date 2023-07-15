--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Ada.Unchecked_Conversion;
with System;

package body Support.Stream_Byte_Arrays
is

   procedure Read_Byte_Array
     (Stream : in out Ada.Streams.Root_Stream_Type'Class;
      Item   : in out Tux.Types.Byte_Array;
      Length :    out Natural)
   is
      use type Ada.Streams.Stream_Element_Offset;

      Item_Size : constant Ada.Streams.Stream_Element_Offset :=
        Item'Size / Ada.Streams.Stream_Element'Size;

      type SEA_Access is access all
        Ada.Streams.Stream_Element_Array (0 .. Item_Size - 1);

      function To_SEA_Access is new Ada.Unchecked_Conversion
        (Source => System.Address,
         Target => SEA_Access);

      Item_Access : constant SEA_Access := To_SEA_Access (Item'Address);

      Last : Ada.Streams.Stream_Element_Offset;
   begin
      Ada.Streams.Read (Stream, Item_Access.all, Last => Last);

      Length := Natural ((Last - Item_Access.all'First) + 1);
   end Read_Byte_Array;

end Support.Stream_Byte_Arrays;
