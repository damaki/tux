--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
package body Tux.XOF with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   ----------------
   -- Initialize --
   ----------------

   procedure Initialize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHAKE128 =>
            SHAKE.Initialize (Ctx.SHAKE128_Ctx);
         when SHAKE256 =>
            SHAKE.Initialize (Ctx.SHAKE256_Ctx);
      end case;
   end Initialize;

   ------------
   -- Update --
   ------------

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   is
   begin
      case Ctx.Algorithm is
         when SHAKE128 =>
            SHAKE.Update (Ctx.SHAKE128_Ctx, Data);
         when SHAKE256 =>
            SHAKE.Update (Ctx.SHAKE256_Ctx, Data);
      end case;
   end Update;

   -------------
   -- Extract --
   -------------

   procedure Extract
     (Ctx    : in out Context;
      Digest :    out Byte_Array)
   is
   begin
      case Ctx.Algorithm is
         when SHAKE128 =>
            SHAKE.Extract (Ctx.SHAKE128_Ctx, Digest);
         when SHAKE256 =>
            SHAKE.Extract (Ctx.SHAKE256_Ctx, Digest);
      end case;
   end Extract;

   ------------------------
   -- Extract_And_Verify --
   ------------------------

   procedure Extract_And_Verify
     (Ctx             : in out Context;
      Expected_Digest :        Byte_Array;
      Valid           :    out Boolean)
   is
      BLen : constant Block_Length_Number := Block_Length (Ctx.Algorithm);

      Buffer : Byte_Array (1 .. BLen) with Relaxed_Initialization;

      Offset    : Byte_Count := 0;
      Remaining : Byte_Count := Expected_Digest'Length;
      Length    : Byte_Count;
      F         : Index_Number;
      L         : Index_Number;

   begin
      --  The Expected_Digest could be arbitrarily large so we compare the
      --  output in smaller chunks.
      --
      --  This loop is designed to run in constant time. The loop continues
      --  iterating and checking the entire output, even if a mismatch occurred
      --  earler in the output.

      Valid := True;

      while Remaining > 0 loop
         pragma Loop_Variant (Decreases => Remaining);
         pragma Loop_Invariant (Offset + Remaining = Expected_Digest'Length);

         Length := Byte_Count'Min (Buffer'Length, Remaining);

         Extract (Ctx, Buffer (1 .. Length));

         F := Expected_Digest'First + Offset;
         L := F + Length - 1;

         Valid := Valid and Equal_Constant_Time
                              (Buffer (1 .. Length), Expected_Digest (F .. L));

         Offset    := Offset    + Length;
         Remaining := Remaining - Length;
      end loop;

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Buffer);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Buffer);
   end Extract_And_Verify;

   --------------
   -- Sanitize --
   --------------

   procedure Sanitize (Ctx : out Context) is
   begin
      case Ctx.Algorithm is
         when SHAKE128 =>
            SHAKE.Sanitize (Ctx.SHAKE128_Ctx);
         when SHAKE256 =>
            SHAKE.Sanitize (Ctx.SHAKE256_Ctx);
      end case;
   end Sanitize;

   --------------------
   -- Compute_Digest --
   --------------------

   procedure Compute_Digest
     (Algorithm :     Enabled_Algorithm_Kind;
      Data      :     Byte_Array;
      Digest    : out Byte_Array)
   is
      Ctx : Context (Algorithm);
   begin
      Initialize (Ctx);
      Update (Ctx, Data);
      Extract (Ctx, Digest);

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Ctx);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Ctx);
   end Compute_Digest;

   -------------------
   -- Verify_Digest --
   -------------------

   function Verify_Digest
     (Algorithm       : Enabled_Algorithm_Kind;
      Data            : Byte_Array;
      Expected_Digest : Byte_Array)
      return Boolean
   is
      Ctx   : Context (Algorithm);
      Valid : Boolean;
   begin
      Initialize (Ctx);
      Update (Ctx, Data);
      Extract_And_Verify (Ctx, Expected_Digest, Valid);

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      Sanitize (Ctx);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Ctx);

      return Valid;
   end Verify_Digest;

end Tux.XOF;
