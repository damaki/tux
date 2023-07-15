--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces; use Interfaces;

package body Tux.HKDF with
  SPARK_Mode
is

   ------------
   -- Lemmas --
   ------------

   procedure Lemma_Add_Mod_Preserve
     (N : Natural;
      D : Positive)
   with
     Ghost,
     Pre  => N mod D = 0 and N <= Natural'Last - D,
     Post => (N + D) mod D = 0;

   ----------------------------
   -- Lemma_Add_Mod_Preserve --
   ----------------------------

   procedure Lemma_Add_Mod_Preserve
     (N : Natural;
      D : Positive)
   is
   begin
      null;
   end Lemma_Add_Mod_Preserve;

   ----------
   -- HKDF --
   ----------

   procedure HKDF
     (Algorithm :     Hashing.Enabled_Algorithm_Kind;
      Salt      :     Byte_Array;
      IKM       :     Byte_Array;
      Info      :     Byte_Array;
      OKM       : out Byte_Array)
   is
      Length : constant PRK_Length_Number := PRK_Length (Algorithm);

      PRK : Byte_Array (1 .. Length) with Relaxed_Initialization;

   begin
      Extract (Algorithm => Algorithm,
               Salt      => Salt,
               IKM       => IKM,
               PRK       => PRK);

      Expand (Algorithm => Algorithm,
              PRK       => PRK,
              Info      => Info,
              OKM       => OKM);
   end HKDF;

   -------------
   -- Extract --
   -------------

   procedure Extract
     (Algorithm :     Hashing.Enabled_Algorithm_Kind;
      Salt      :     Byte_Array;
      IKM       :     Byte_Array;
      PRK       : out Byte_Array)
   is
      Hash_Length : constant Hashing.Hash_Length_Number :=
                      Hashing.Hash_Length (Algorithm);

      Null_Salt : Byte_Array (1 .. Hash_Length);

   begin
      if Salt'Length > 0 then
         HMAC.Compute_HMAC (Algorithm, Salt, IKM, PRK);
      else
         --  RFC 5869 Section 2.2:
         --  If the salt is not provided, then it is set to a string of
         --  HashLen zeroes.

         Null_Salt := (others => 0);
         HMAC.Compute_HMAC (Algorithm, Null_Salt, IKM, PRK);
      end if;
   end Extract;

   ------------
   -- Expand --
   ------------

   procedure Expand
     (Algorithm :     Hashing.Enabled_Algorithm_Kind;
      PRK       :     Byte_Array;
      Info      :     Byte_Array;
      OKM       : out Byte_Array)
   is
      Hash_Length : constant Hashing.Hash_Length_Number :=
                      Hashing.Hash_Length (Algorithm);

      Ctx : HMAC.Context (Algorithm);

      T        : Byte_Array (1 .. Hash_Length) with Relaxed_Initialization;
      T_Length : Hashing.Hash_Length_Number'Base := 0;

      Offset    : OKM_Length_Number := 0;
      Remaining : OKM_Length_Number := OKM'Length;
      Pos       : Index_Number;

      --  L = OKM'Length (does not exceed 255 * Hash_Length)
      --  N = ceil (L / Hash_Length)

      N : Natural range 1 .. 255 := 1;

   begin
      while Remaining > 0 loop

         pragma Warnings
           (Off, """OKM"" may be referenced before it has a value",
            Reason => "Initialization verified by GNATprove");

         pragma Warnings
           (Off, """T"" may be referenced before it has a value",
            Reason => "Initialization verified by GNATprove");

         pragma Loop_Variant (Decreases => Remaining);
         pragma Loop_Invariant (if Offset > 0 then T'Initialized);
         pragma Loop_Invariant (Offset + Remaining = OKM'Length);
         pragma Loop_Invariant (Offset = (N - 1) * Hash_Length);
         pragma Loop_Invariant (Offset mod Hash_Length = 0);
         pragma Loop_Invariant (T_Length = (if Offset > 0
                                            then Hash_Length
                                            else 0));
         pragma Loop_Invariant
           (OKM (OKM'First .. OKM'First + Offset - 1)'Initialized);

         pragma Warnings (On);

         --  T = T(1) || T(2) || T(3) || ... || T(N)
         --
         --  T(0) = empty string
         --  T(N) = HMAC(PRK, T(N-1) || Info || N) for arbitrary N > 0

         HMAC.Initialize (Ctx, PRK);
         HMAC.Update (Ctx, T (1 .. T_Length));
         HMAC.Update (Ctx, Info);
         HMAC.Update (Ctx, Byte_Array'(0 => Unsigned_8 (N)));
         HMAC.Finish (Ctx, T);

         --  OKM = first L octets of T (where L = OKM'Length)

         Pos := OKM'First + Offset;

         if Remaining > Hash_Length then
            OKM (Pos .. Pos + (Hash_Length - 1)) := T;
         else
            OKM (Pos .. OKM'Last) := T (1 .. Remaining);
            exit;
         end if;

         T_Length := Hash_Length;
         N        := N + 1;

         Lemma_Add_Mod_Preserve (Offset, Hash_Length);

         Offset    := Offset    + Hash_Length;
         Remaining := Remaining - Hash_Length;
      end loop;

      pragma Warnings (GNATprove, Off, "statement has no effect",
                       Reason => "Sanitizing sensitive data from memory");
      HMAC.Sanitize (Ctx);
      Sanitize (T);
      pragma Warnings (GNATprove, On);

      pragma Unreferenced (Ctx);
      pragma Unreferenced (T);
   end Expand;

end Tux.HKDF;
