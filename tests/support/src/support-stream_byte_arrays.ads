--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Ada.Streams;
with Tux.Types;

package Support.Stream_Byte_Arrays
is

   procedure Read_Byte_Array
      (Stream : in out Ada.Streams.Root_Stream_Type'Class;
       Item   : in out Tux.Types.Byte_Array;
       Length :    out Natural);
   --  Efficiently read bytes from a stream.
   --
   --  This procedure will read as many bytes as possible to fill the Item
   --  buffer. The Length parameter is set to the number of bytes that were
   --  read.

end Support.Stream_Byte_Arrays;
