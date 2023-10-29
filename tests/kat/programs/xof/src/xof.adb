--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This program reads bytes from the standard input, hashes it using the
--  XOF algorithm specified on the command line, and prints the computed digest
--  as a hexadecimal string to the standard output.

with Ada.Command_Line;   use Ada.Command_Line;
with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Streams.Stream_IO;
with Ada.Streams.Stream_IO.C_Streams;
with Interfaces.C_Streams; use Interfaces.C_Streams;

with Tux.XOF;    use Tux.XOF;
with Tux.Types;

with Support.Stream_Byte_Arrays;
with Support.Hex_Strings;

procedure XOF is
   Algo    : Tux.XOF.Algorithm_Kind;
   File    : Ada.Streams.Stream_IO.File_Type;
   Out_Len : Positive;
   Length  : Natural;

begin
   --  Check arguments

   if Argument_Count /= 2 then
      Put_Line ("usage: xof ALGO_NAME OUTPUT_LENGTH");
      Set_Exit_Status (1);
      return;
   end if;

   --  Convert from String to Algorithm_Kind

   declare
   begin
      Algo := Tux.XOF.Algorithm_Kind'Value (Argument (1));
   exception
      when Constraint_Error =>
         Put_Line (Standard_Error, "Unknown algorithm: " & Argument (1));
         Set_Exit_Status (1);
         return;
   end;

   --  Get the output length

   declare
   begin
      Out_Len := Positive'Value (Argument (2));
   exception
      when Constraint_Error =>
         Put_Line (Standard_Error, "Invalid output length: " & Argument (2));
         Set_Exit_Status (1);
         return;
   end;

   --  Check that the selected algorithm is enabled in the crate configuration

   if Algo not in Tux.XOF.Enabled_Algorithm_Kind then
      Put_Line (Standard_Error, "Algorithm " & Argument (1) & " is disabled");
      Set_Exit_Status (2);
      return;
   end if;

   --  Hash the contents of the standard input

   Ada.Streams.Stream_IO.C_Streams.Open
     (File     => File,
      Mode     => Ada.Streams.Stream_IO.In_File,
      C_Stream => stdin);

   set_binary_mode (fileno (Ada.Streams.Stream_IO.C_Streams.C_Stream (File)));

   declare
      Ctx : Tux.XOF.Context (Algo);

      Buffer : Tux.Types.Byte_Array (1 .. 4096);

      Remaining : Natural := Out_Len;

   begin
      --  Hash the contents of the standard input

      Tux.XOF.Initialize (Ctx);
      loop
         Support.Stream_Byte_Arrays.Read_Byte_Array
            (Stream => Ada.Streams.Stream_IO.Stream (File).all,
            Item   => Buffer,
            Length => Length);

         exit when Length = 0;

         Tux.XOF.Update (Ctx, Buffer (1 .. Length));
      end loop;

      while Remaining > 0 loop
         Length := Natural'Min (Remaining, Buffer'Length);

         Tux.XOF.Extract (Ctx, Buffer (1 .. Length));

         Support.Hex_Strings.Print_Hex_String (Buffer (1 .. Length));

         Remaining := Remaining - Length;
      end loop;
   end;
end XOF;
