--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This program produces the "Monte Carlo" test defined in Section 6.3.3
--  of the NIST Secure Has Algorithm 3 Validation System (SHA3VS).
--
--  This program takes an initial seed, then generates 100,000 outputs.
--  Every 1,000th output is printed to the standard output as a checkpoint.

with Ada.Command_Line;   use Ada.Command_Line;
with Ada.Text_IO;        use Ada.Text_IO;

with Tux.XOF;    use Tux.XOF;
with Tux.Types;

with Support.Hex_Strings;

procedure XOF_Monte is

   function To_U16_BE (Bytes : Tux.Types.Byte_Array) return Natural is
     (Natural (Bytes (Bytes'First + 1))
      + (Natural (Bytes (Bytes'First)) * 256));
   --  Convert 16 bits to an integer (big endian)

   Algo          : Tux.XOF.Algorithm_Kind;
   Min_Out_Bytes : Positive;
   Max_Out_Bytes : Positive;

begin
   --  Check arguments

   if Argument_Count /= 4 then
      Put_Line ("usage: xof_monte ALGO_NAME minoutbytes maxoutbytes seed");
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

   --  Get the lengths

   declare
   begin
      Min_Out_Bytes := Positive'Value (Argument (2));
   exception
      when Constraint_Error =>
         Put_Line (Standard_Error, "Invalid minoutbytes: " & Argument (2));
         Set_Exit_Status (1);
         return;
   end;

   declare
   begin
      Max_Out_Bytes := Positive'Value (Argument (3));
   exception
      when Constraint_Error =>
         Put_Line (Standard_Error, "Invalid maxoutbytes: " & Argument (3));
         Set_Exit_Status (1);
         return;
   end;

   --  Check that the selected algorithm is enabled in the crate configuration

   if Algo not in Tux.XOF.Enabled_Algorithm_Kind then
      Put_Line (Standard_Error, "Algorithm " & Argument (1) & " is disabled");
      Set_Exit_Status (2);
      return;
   end if;

   declare
      Seed_Hex : constant String := Argument (4);

      Seed : Tux.Types.Byte_Array (1 .. 16);
      --  SHA3VS specifies that the initial message (seed) is 128 bits long

      Ctx : Tux.XOF.Context (Algo);

      Out_Len   : Positive;
      Out_Len_J : Positive;

      type Byte_Array_Access is access Tux.Types.Byte_Array;

      Output : constant Byte_Array_Access :=
                 new Tux.Types.Byte_Array (1 .. Max_Out_Bytes);

      MC_Range : constant Positive := Max_Out_Bytes - Min_Out_Bytes + 1;

   begin
      if Seed_Hex'Length /= Seed'Length * 2
        or else not Support.Hex_Strings.Valid_Hex_String (Seed_Hex)
      then
         Put_Line (Standard_Error, "Invalid seed " & Seed_Hex);
         Put_Line (Standard_Error, "Seed must be a 16 byte hex string");
         Set_Exit_Status (1);
         return;
      end if;

      Support.Hex_Strings.Parse_Hex_String (Seed_Hex, Seed);

      --  Initial Outputlen = (floor(maxoutlen/8) )*8

      Out_Len := Max_Out_Bytes;

      --  Output_0 = Msg (seed)

      Output.all (1 .. Seed'Length) := Seed;

      for J in 1 .. 100 loop
         for I in 1 .. 1000 loop
            --  Msg_i = 128 leftmost bits of Output_i-1
            --  Output_i = SHAKE(Msg_i, Outputlen)

            Tux.XOF.Initialize (Ctx);
            Tux.XOF.Update (Ctx, Output.all (1 .. 16));
            Tux.XOF.Extract (Ctx, Output.all (1 .. Out_Len));

            if I = 1000 then
               Out_Len_J := Out_Len;
            end if;

            --  SHA3VS Section 6.3.3 (1):
            --  "If the previous output has less than 128 bits, then zeroes are
            --  concatenated to the end of the bits of output".

            if Out_Len < 16 then
               Output.all (Out_Len + 1 .. 16) := (others => 0);
            end if;

            --  Range = (maxoutbytes – minoutbytes + 1)
            --  Outputlen = minoutbytes + (Rightmost_Output_bits mod Range)

            Out_Len :=
               Min_Out_Bytes +
               (To_U16_BE (Output.all (Out_Len - 1 .. Out_Len)) mod MC_Range);
         end loop;

         if J > 1 then
            New_Line;
         end if;

         Support.Hex_Strings.Print_Hex_String (Output.all (1 .. Out_Len_J));
      end loop;
   end;
end XOF_Monte;
