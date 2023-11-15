--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This is the implementation optimized for code size. The Num_Rounds
--  parameter for Generic_Permute is known only at run-time so that the
--  generic is instantiated only once.

package body Tux.Keccak_1600 with
  SPARK_Mode
is

   procedure Permute
     (Ctx        : in out Keccak.Context;
      Num_Rounds :        Keccak.Round_Count);

   -------------
   -- Permute --
   -------------

   procedure Permute
     (Ctx        : in out Keccak.Context;
      Num_Rounds :        Keccak.Round_Count)
   is
      procedure P is new Keccak.Generic_Permute (Num_Rounds);
   begin
      P (Ctx);
   end Permute;

   ----------------
   -- Permute_24 --
   ----------------

   procedure Permute_24 (Ctx : in out Keccak.Context) is
   begin
      Permute (Ctx, Num_Rounds => 24);
   end Permute_24;

   ----------------
   -- Permute_12 --
   ----------------

   procedure Permute_12 (Ctx : in out Keccak.Context) is
   begin
      Permute (Ctx, Num_Rounds => 12);
   end Permute_12;

end Tux.Keccak_1600;