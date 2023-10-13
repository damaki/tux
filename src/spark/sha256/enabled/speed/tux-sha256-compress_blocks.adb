--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
separate (Tux.SHA256)
procedure Compress_Blocks
  (State  : in out State_Array;
   Blocks :        Byte_Array)
is
   Remaining : Byte_Count := Blocks'Length;
   Offset    : Byte_Count := 0;

   Pos : Natural;

   W : U32_Array (0 .. 63) with Relaxed_Initialization;
   J : Natural range 0 .. 64;

   Temp_State : State_Array;

   A : Unsigned_32 renames Temp_State (0);
   B : Unsigned_32 renames Temp_State (1);
   C : Unsigned_32 renames Temp_State (2);
   D : Unsigned_32 renames Temp_State (3);
   E : Unsigned_32 renames Temp_State (4);
   F : Unsigned_32 renames Temp_State (5);
   G : Unsigned_32 renames Temp_State (6);
   H : Unsigned_32 renames Temp_State (7);

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

         Pos   := Blocks'First + Offset + (I * 4);
         W (I) := To_U32_BE (Blocks (Pos .. Pos + 3));
      end loop;

      pragma Assert (W (0 .. 15)'Initialized);

      Temp_State := State;

      J := 0;
      while J < 16 loop
         pragma Loop_Variant (Increases => J);
         pragma Loop_Invariant (J mod 8 = 0);

         Transform (A, B, C, D, E, F, G, H, W (J),     Round_K (J));
         Transform (H, A, B, C, D, E, F, G, W (J + 1), Round_K (J + 1));
         Transform (G, H, A, B, C, D, E, F, W (J + 2), Round_K (J + 2));
         Transform (F, G, H, A, B, C, D, E, W (J + 3), Round_K (J + 3));
         Transform (E, F, G, H, A, B, C, D, W (J + 4), Round_K (J + 4));
         Transform (D, E, F, G, H, A, B, C, W (J + 5), Round_K (J + 5));
         Transform (C, D, E, F, G, H, A, B, W (J + 6), Round_K (J + 6));
         Transform (B, C, D, E, F, G, H, A, W (J + 7), Round_K (J + 7));

         J := J + 8;
      end loop;

      while J < 64 loop
         pragma Loop_Variant (Increases => J);
         pragma Loop_Invariant (J >= 16);
         pragma Loop_Invariant (J mod 8 = 0);
         pragma Loop_Invariant (W (0 .. J - 1)'Initialized);

         W (J) := R (J, W (0 .. J - 1));
         Transform (A, B, C, D, E, F, G, H, W (J), Round_K (J));

         W (J + 1) := R (J + 1, W (0 .. J));
         Transform (H, A, B, C, D, E, F, G, W (J + 1), Round_K (J + 1));

         W (J + 2) := R (J + 2, W (0 .. J + 1));
         Transform (G, H, A, B, C, D, E, F, W (J + 2), Round_K (J + 2));

         W (J + 3) := R (J + 3, W (0 .. J + 2));
         Transform (F, G, H, A, B, C, D, E, W (J + 3), Round_K (J + 3));

         W (J + 4) := R (J + 4, W (0 .. J + 3));
         Transform (E, F, G, H, A, B, C, D, W (J + 4), Round_K (J + 4));

         W (J + 5) := R (J + 5, W (0 .. J + 4));
         Transform (D, E, F, G, H, A, B, C, W (J + 5), Round_K (J + 5));

         W (J + 6) := R (J + 6, W (0 .. J + 5));
         Transform (C, D, E, F, G, H, A, B, W (J + 6), Round_K (J + 6));

         W (J + 7) := R (J + 7, W (0 .. J + 6));
         Transform (B, C, D, E, F, G, H, A, W (J + 7), Round_K (J + 7));

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
   pragma Warnings (On);

   pragma Unreferenced (A, B, C, D, E, F, G, H, W, Temp_State);
end Compress_Blocks;
