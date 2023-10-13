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

   W : Types.U64_Array (0 .. 79) with Relaxed_Initialization;
   J : Natural;

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

      for I in Natural range 0 .. 15 loop
         pragma Warnings (GNAT, Off,
                        """W"" may be referenced before it has a value",
                        Reason => "Initialization of W is verified via proof");
         pragma Loop_Invariant (W (0 .. I - 1)'Initialized);
         pragma Warnings (GNAT, On);

         Pos   := Blocks'First + Offset + (I * 8);
         W (I) := To_U64_BE (Blocks (Pos .. Pos + 7));
      end loop;

      pragma Assert (W (0 .. 15)'Initialized);

      for I in Natural range 16 .. 79 loop
         pragma Loop_Invariant (W (0 .. I - 1)'Initialized);

         W (I) := R (I, W (0 .. I - 1));
      end loop;

      Temp_State := State;

      J := 0;
      while J < 80 loop
         pragma Loop_Variant (Increases => J);
         pragma Loop_Invariant (J mod 8 = 0);

         Transform (A, B, C, D, E, F, G, H, W (J),     K (J));
         Transform (H, A, B, C, D, E, F, G, W (J + 1), K (J + 1));
         Transform (G, H, A, B, C, D, E, F, W (J + 2), K (J + 2));
         Transform (F, G, H, A, B, C, D, E, W (J + 3), K (J + 3));
         Transform (E, F, G, H, A, B, C, D, W (J + 4), K (J + 4));
         Transform (D, E, F, G, H, A, B, C, W (J + 5), K (J + 5));
         Transform (C, D, E, F, G, H, A, B, W (J + 6), K (J + 6));
         Transform (B, C, D, E, F, G, H, A, W (J + 7), K (J + 7));

         J := J + 8;
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

   pragma Unreferenced (A, B, C, D, E, F, G, H, W, Temp_State);
end Compress_Blocks;
