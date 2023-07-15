--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This program reads bytes from the standard input, hashes it using the
--  algorithm specified on the command line, and prints the computed hash
--  as a hexadecimal string to the standard output.
--
--  If the --monte switch is given, then the standard input data is used as
--  the seed to the Monte Carlo computation.

with Ada.Command_Line;   use Ada.Command_Line;
with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Streams.Stream_IO;
with Ada.Streams.Stream_IO.C_Streams;
with Interfaces.C_Streams; use Interfaces.C_Streams;

with Tux.Hashing;    use Tux.Hashing;
with Tux.Types;

with Support.Stream_Byte_Arrays;
with Support.Hex_Strings;

procedure Hash is

   Algo        : Tux.Hashing.Algorithm_Kind;
   File        : Ada.Streams.Stream_IO.File_Type;
   Length      : Natural;
   Buffer      : Tux.Types.Byte_Array (1 .. 4096);
   Monte_Carlo : Boolean := False;

begin
   --  Check arguments

   if Argument_Count not in 1 .. 2 then
      Put_Line ("usage: hash ALGO_NAME [--monte]");
      Set_Exit_Status (1);
      return;
   end if;

   if Argument_Count = 2 then
      if Argument (2) = "--monte" then
         Monte_Carlo := True;
      else
         Put_Line (Standard_Error, "Unknown option: " & Argument (2));
         Set_Exit_Status (1);
      end if;
   end if;

   --  Convert from String to Algorithm_Kind

   declare
   begin
      Algo := Tux.Hashing.Algorithm_Kind'Value (Argument (1));
   exception
      when Constraint_Error =>
         Put_Line (Standard_Error, "Unknown algorithm: " & Argument (1));
         Set_Exit_Status (1);
         return;
   end;

   --  Check that the selected algorithm is enabled in the crate configuration

   if Algo not in Tux.Hashing.Enabled_Algorithm_Kind then
      Put_Line (Standard_Error, "Algorithm " & Argument (1) & " is disabled");
      Set_Exit_Status (2);
   end if;

   --  Hash the contents of the standard input

   Ada.Streams.Stream_IO.C_Streams.Open
     (File     => File,
      Mode     => Ada.Streams.Stream_IO.In_File,
      C_Stream => stdin);

   set_binary_mode (fileno (Ada.Streams.Stream_IO.C_Streams.C_Stream (File)));

   declare
      use type Tux.Types.Byte_Array;

      Ctx : Tux.Hashing.Context (Algo);

      Hash_Length   : constant Hash_Length_Number :=
                        Tux.Hashing.Hash_Length (Algo);
      A, B, C, Hash : Tux.Types.Byte_Array (1 .. Hash_Length);

   begin
      if not Monte_Carlo then
         --  Hash the contents of the standard input
         Tux.Hashing.Initialize (Ctx);
         loop
            Support.Stream_Byte_Arrays.Read_Byte_Array
              (Stream => Ada.Streams.Stream_IO.Stream (File).all,
               Item   => Buffer,
               Length => Length);

            exit when Length = 0;

            Tux.Hashing.Update (Ctx, Buffer (1 .. Length));
         end loop;

         Tux.Hashing.Finish (Ctx, Hash);
         Support.Hex_Strings.Print_Hex_String (Hash);
      else
         --  Monte Carlo mode. The seed is received via the standard input

         Support.Stream_Byte_Arrays.Read_Byte_Array
           (Stream => Ada.Streams.Stream_IO.Stream (File).all,
            Item   => Buffer,
            Length => Length);

         if Length /= Hash_Length then
            Put (Standard_Error, "Invalid seed. Length must be");
            Put (Standard_Error, Integer'Image (Hash_Length));
            Put (Standard_Error, " bytes");
            New_Line (Standard_Error);
            Set_Exit_Status (1);
            return;
         end if;

         A := Buffer (1 .. Hash_Length);
         B := Buffer (1 .. Hash_Length);
         C := Buffer (1 .. Hash_Length);

         for I in 1 .. 1000 loop
            Tux.Hashing.Initialize (Ctx);
            Tux.Hashing.Update (Ctx, A & B & C);
            Tux.Hashing.Finish (Ctx, Hash);

            A := B;
            B := C;
            C := Hash;
         end loop;

         Support.Hex_Strings.Print_Hex_String (Hash);
      end if;
   end;
end Hash;
