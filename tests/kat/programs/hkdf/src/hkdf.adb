--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This program performs an HKDF computation and prints the generated
--  output keying material (OKM) to the standard output.
--
--  The inputs provided via the command line are:
--    1. The hash function to use, e.g. SHA256
--    2. The input keying material (IKM) as a hex string.
--    3. The info as a hex string.
--    4. The length of the output keying material (OKM) to generate, in bytes.
--    5. (optional) The salt as a hex string.
--
--  The generated OKM is printed to the standard output as a hex string.

with Ada.Command_Line;   use Ada.Command_Line;
with Ada.Exceptions;     use Ada.Exceptions;
with Ada.Text_IO;        use Ada.Text_IO;

with Tux.Hashing;
with Tux.HKDF;
with Tux.Types;

with Support.Hex_Strings;

procedure Hkdf is
   Algo : Tux.Hashing.Algorithm_Kind;

begin
   --  Check arguments

   if Argument_Count not in 4 .. 5 then
      Put_Line ("usage: hash HASH_ALGO_NAME IKM INFO OKMLen [SALT]");
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
   end if;

   --  Parse the key given from the command line

   declare
      OKM_Length : constant Natural := Natural'Value (Argument (4));

      IKM_String  : constant String := Argument (2);
      Info_String : constant String := Argument (3);
      Salt_String : constant String := (if Argument_Count >= 5
                                        then Argument (5)
                                        else "");

      IKM_Bytes  : Tux.Types.Byte_Array (1 .. IKM_String'Length  / 2);
      Info_Bytes : Tux.Types.Byte_Array (1 .. Info_String'Length / 2);
      Salt_Bytes : Tux.Types.Byte_Array (1 .. Salt_String'Length / 2);
      OKM        : Tux.Types.Byte_Array (1 .. OKM_Length);

   begin
      if IKM_String'Length mod 2 /= 0 then
         Put_Line (Standard_Error, "Invalid IKM hex string length");
         Set_Exit_Status (1);
         return;
      end if;

      if Info_String'Length mod 2 /= 0 then
         Put_Line (Standard_Error, "Invalid Info hex string length");
         Set_Exit_Status (1);
         return;
      end if;

      if Salt_String'Length mod 2 /= 0 then
         Put_Line (Standard_Error, "Invalid Salt hex string length");
         Set_Exit_Status (1);
         return;
      end if;

      Support.Hex_Strings.Parse_Hex_String (IKM_String,  IKM_Bytes);
      Support.Hex_Strings.Parse_Hex_String (Info_String, Info_Bytes);
      Support.Hex_Strings.Parse_Hex_String (Salt_String, Salt_Bytes);

      Tux.HKDF.HKDF (Algo, Salt_Bytes, IKM_Bytes, Info_Bytes, OKM);

      Support.Hex_Strings.Print_Hex_String (OKM);

   exception
      when Error : Constraint_Error =>
         Put_Line (Standard_Error, Exception_Message (Error));
         Set_Exit_Status (1);
         return;
   end;
end Hkdf;
