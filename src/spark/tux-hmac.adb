--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces; use Interfaces;

package body Tux.HMAC with
  SPARK_Mode
is

   --------------------
   -- HMAC Constants --
   --------------------

   Outer_Pad : constant Unsigned_8 := 16#5C#;
   Inner_Pad : constant Unsigned_8 := 16#36#;

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize
     (Ctx : out Context;
      Key :     Byte_Array)
   is
      Block_Length : constant Hashing.Block_Length_Number :=
        Hashing.Block_Length (Ctx.Algorithm);

      Hash_Length : constant Hashing.Hash_Length_Number :=
        Hashing.Hash_Length (Ctx.Algorithm);

      Block : Byte_Array (1 .. Block_Length) with Relaxed_Initialization;

   begin

      --  HMAC(Key, M) = H((Key' xor opad) || H((Key' xor ipad) || M))

      --  Key' = H(Key) if Key'Length larger than block size
      --       = Key otherwise

      if Key'Length > Block_Length then
         Hashing.Initialize (Ctx.Outer_Ctx);
         Hashing.Update (Ctx.Outer_Ctx, Key);
         Hashing.Finish (Ctx.Outer_Ctx, Block (1 .. Hash_Length));

         pragma Assert_And_Cut
           (Ctx.Inner_Ctx.Algorithm = Ctx.Outer_Ctx.Algorithm
            and Block (1 .. Hash_Length)'Initialized);

         Block (Hash_Length + 1 .. Block'Last) := (others => 0);
      else
         Block (1 .. Key'Length)              := Key;
         Block (Key'Length + 1 .. Block'Last) := (others => 0);
      end if;

      pragma Assert_And_Cut
        (Ctx.Inner_Ctx.Algorithm = Ctx.Outer_Ctx.Algorithm
         and Block'Initialized);

      --  Key' xor opad

      for B of Block loop
         pragma Loop_Invariant (Block'Initialized);

         B := B xor Outer_Pad;
      end loop;

      pragma Assert_And_Cut
        (Ctx.Inner_Ctx.Algorithm = Ctx.Outer_Ctx.Algorithm
         and Block'Initialized);

      Hashing.Initialize (Ctx.Outer_Ctx);
      Hashing.Update (Ctx.Outer_Ctx, Block);

      pragma Assert_And_Cut
        (Ctx.Inner_Ctx.Algorithm = Ctx.Outer_Ctx.Algorithm
         and Block'Initialized
         and not Hashing.Finished (Ctx.Outer_Ctx));

      --  Key' xor ipad

      for B of Block loop
         pragma Loop_Invariant (Block'Initialized);

         --  XOR Outer_Pad again to cancel out previous Outer_Pad:
         --    (B xor Outer_Pad) xor (Outer_Pad xor Inner_Pad)
         --  is equivalent to:
         --    B xor (Outer_Pad xor Outer_Pad) xor Inner_Pad
         --  = B xor 0 xor Inner_Pad
         --  = B xor Inner_Pad

         B := B xor (Outer_Pad xor Inner_Pad);
      end loop;

      pragma Assert_And_Cut
        (Ctx.Inner_Ctx.Algorithm = Ctx.Outer_Ctx.Algorithm
         and Block'Initialized
         and not Hashing.Finished (Ctx.Outer_Ctx));

      Hashing.Initialize (Ctx.Inner_Ctx);
      Hashing.Update (Ctx.Inner_Ctx, Block);

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Block);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Block);
   end Initialize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
   begin
      Hashing.Update (Ctx.Inner_Ctx, Data);
   end Update;

   ------------
   -- Finish --
   ------------

   procedure Finish
     (Ctx : in out Context;
      MAC :    out Byte_Array)
   is
   begin
      Hashing.Finish (Ctx.Inner_Ctx, MAC);
      Hashing.Update (Ctx.Outer_Ctx, MAC);
      Hashing.Finish (Ctx.Outer_Ctx, MAC);
   end Finish;

   -----------------------
   -- Finish_And_Verify --
   -----------------------

   procedure Finish_And_Verify
     (Ctx          : in out Context;
      Expected_MAC :        Byte_Array;
      Valid        :    out Boolean)
   is
      MLen : constant HMAC_Length_Number := HMAC_Length (Ctx.Algorithm);
      MAC  : Byte_Array (1 .. MLen);

   begin
      Finish (Ctx, MAC);

      Valid := Equal_Constant_Time
                 (Expected_MAC, MAC (1 .. Expected_MAC'Length));

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (MAC);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (MAC);
   end Finish_And_Verify;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      Hashing.Sanitize (Ctx.Inner_Ctx);
      Hashing.Sanitize (Ctx.Outer_Ctx);

      pragma Assert_And_Cut
        (Hashing.Finished (Ctx.Inner_Ctx)
         and Hashing.Finished (Ctx.Outer_Ctx));
   end Sanitize;

   ------------------
   -- Compute_HMAC --
   ------------------

   procedure Compute_HMAC
     (Algorithm :     Hashing.Enabled_Algorithm_Kind;
      Key       :     Byte_Array;
      Data      :     Byte_Array;
      MAC       : out Byte_Array)
   is
      Ctx : Context (Algorithm);

   begin
      Initialize (Ctx, Key);
      Update (Ctx, Data);
      Finish (Ctx, MAC);

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Ctx);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Ctx);
   end Compute_HMAC;

   -----------------
   -- Verify_HMAC --
   -----------------

   function Verify_HMAC
     (Algorithm    : Hashing.Enabled_Algorithm_Kind;
      Key          : Byte_Array;
      Data         : Byte_Array;
      Expected_MAC : Byte_Array)
      return Boolean
   is
      MLen  : constant HMAC_Length_Number := HMAC_Length (Algorithm);
      MAC   : Byte_Array (1 .. MLen);
      Valid : Boolean;

   begin
      Compute_HMAC (Algorithm, Key, Data, MAC);

      Valid := Equal_Constant_Time
                 (Expected_MAC, MAC (1 .. Expected_MAC'Length));

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (MAC);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (MAC);

      return Valid;
   end Verify_HMAC;

end Tux.HMAC;
