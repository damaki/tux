--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
separate (Tux.SHA512)
procedure Compress_Blocks
  (State  : in out State_Array;
   Blocks :        Byte_Array)
is
   Remaining : Byte_Count := Blocks'Length;
   Offset    : Byte_Count := 0;

   Pos : Natural;

   Temp : Unsigned_64;
   W    : U64_Array (0 .. 79) with Relaxed_Initialization;

   Temp_State : State_Array;

   A : Unsigned_64 renames Temp_State (0);
   B : Unsigned_64 renames Temp_State (1);
   C : Unsigned_64 renames Temp_State (2);
   D : Unsigned_64 renames Temp_State (3);
   E : Unsigned_64 renames Temp_State (4);
   F : Unsigned_64 renames Temp_State (5);
   G : Unsigned_64 renames Temp_State (6);
   H : Unsigned_64 renames Temp_State (7);

begin
   while Remaining > 0 loop
      pragma Loop_Variant (Decreases => Remaining);
      pragma Loop_Invariant (Offset + Remaining = Blocks'Length);
      pragma Loop_Invariant (Offset mod Block_Length = 0);

      Temp_State := State;

      for I in Natural range 0 .. 79 loop
         pragma Warnings (GNAT, Off,
                        """W"" may be referenced before it has a value",
                        Reason => "Initialization of W is verified via proof");
         pragma Loop_Invariant (W (0 .. I - 1)'Initialized);
         pragma Warnings (GNAT, On);

         if I < 16 then
            Pos := Blocks'First + Offset + (I * 8);
            W (I) := To_U64_BE (Blocks (Pos .. Pos + 7));
         else
            W (I) := R (I, W (0 .. I - 1));
         end if;

         Transform (A, B, C, D, E, F, G, H, W (I), K (I));

         Temp := H;
         H := G;
         G := F;
         F := E;
         E := D;
         D := C;
         C := B;
         B := A;
         A := Temp;
      end loop;

      for I in State'Range loop
         State (I) := State (I) + Temp_State (I);
      end loop;

      Offset    := Offset    + Block_Length;
      Remaining := Remaining - Block_Length;
   end loop;

   pragma Warnings (GNATprove, Off, "statement has no effect",
                    Reason => "Sanitizing sensitive data from memory");
   Sanitize (W);
   Sanitize (Temp_State);
   pragma Warnings (GNATprove, On);

   pragma Unreferenced (W, Temp_State);
end Compress_Blocks;
