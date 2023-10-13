--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This program computes the HMAC of bytes read from the standard input.
--  The inputs passed on the command line are:
--    1. The name of the hash algorithm to use, e.g. SHA256
--    2. The key to use, as a hexadecimal string
--    3. The expected MAC, as a hexadecimal string
--
--  The inputs passed via the standard input are:
--    1. The raw message bytes to authenticate
--
--  The output is printed to the standard output in the format:
--     <mac>,<result>
--  where <mac> is the computed HMAC and <result> is the result of comparing
--  the computed <mac> against the expected MAC given on the command line.
--  <result> is either "valid" or "invalid".
--
--  Example output:
--     6b865ba214d6c13e6d7c49f6a347e4e248cfbf73bf138ff16a5567a87063d73b,valid

with Ada.Command_Line;   use Ada.Command_Line;
with Ada.Exceptions;     use Ada.Exceptions;
with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Streams.Stream_IO;
with Ada.Streams.Stream_IO.C_Streams;
with Interfaces.C_Streams; use Interfaces.C_Streams;

with Tux.Hashing;
with Tux.HMAC;
with Tux.Types;

with Support.Stream_Byte_Arrays;
with Support.Hex_Strings;

procedure HMAC is
   Algo   : Tux.Hashing.Algorithm_Kind;
   File   : Ada.Streams.Stream_IO.File_Type;
   Length : Natural;
   Buffer : Tux.Types.Byte_Array (1 .. 4096);

begin
   --  Check arguments

   if Argument_Count /= 3 then
      Put_Line ("usage: hash HASH_ALGO_NAME KEY MAC");
      Set_Exit_Status (1);
      return;
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
      return;
   end if;

   --  Parse the key given from the command line

   declare
      Key_String : constant String := Argument (2);
      Key_Bytes  : Tux.Types.Byte_Array (1 .. Key_String'Length / 2);

      MAC_String : constant String := Argument (3);
      MAC_Bytes  : Tux.Types.Byte_Array (1 .. MAC_String'Length / 2);

      Gen_Ctx    : Tux.HMAC.Context (Algo); --  Context for generating the MAC
      Verify_Ctx : Tux.HMAC.Context (Algo); --  Context for verifying the MAC

   begin
      if Key_String'Length mod 2 /= 0 then
         Put_Line (Standard_Error, "Invalid key");
         Set_Exit_Status (1);
         return;
      end if;

      if MAC_String'Length mod 2 /= 0
         or else MAC_Bytes'Length not in 1 .. Tux.Hashing.Hash_Length (Algo)
      then
         Put_Line (Standard_Error, "Invalid MAC");
         Set_Exit_Status (1);
         return;
      end if;

      Support.Hex_Strings.Parse_Hex_String (Key_String, Key_Bytes);
      Support.Hex_Strings.Parse_Hex_String (MAC_String, MAC_Bytes);

      Tux.HMAC.Initialize (Gen_Ctx,    Key_Bytes);
      Tux.HMAC.Initialize (Verify_Ctx, Key_Bytes);

      --  Process the contents of the standard input

      Ada.Streams.Stream_IO.C_Streams.Open
        (File     => File,
         Mode     => Ada.Streams.Stream_IO.In_File,
         C_Stream => Interfaces.C_Streams.stdin);

      set_binary_mode
        (fileno (Ada.Streams.Stream_IO.C_Streams.C_Stream (File)));

      loop
         Support.Stream_Byte_Arrays.Read_Byte_Array
           (Stream => Ada.Streams.Stream_IO.Stream (File).all,
            Item   => Buffer,
            Length => Length);

         exit when Length = 0;

         Tux.HMAC.Update (Gen_Ctx,    Buffer (1 .. Length));
         Tux.HMAC.Update (Verify_Ctx, Buffer (1 .. Length));
      end loop;

      declare
         HLen  : constant Tux.HMAC.HMAC_Length_Number :=
                   Tux.HMAC.HMAC_Length (Algo);
         Hash  : Tux.Types.Byte_Array (1 .. HLen);
         Valid : Boolean;
      begin
         Tux.HMAC.Finish (Gen_Ctx, Hash);
         Support.Hex_Strings.Print_Hex_String (Hash);
         Put (',');

         Tux.HMAC.Finish_And_Verify (Verify_Ctx, MAC_Bytes, Valid);
         if Valid then
            Put ("valid");
         else
            Put ("invalid");
         end if;
      end;

   exception
      when Error : Constraint_Error =>
         Put_Line (Standard_Error, Exception_Message (Error));
         Set_Exit_Status (1);
         return;
   end;
end HMAC;
