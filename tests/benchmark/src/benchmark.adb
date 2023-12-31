--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Ada.Text_IO;
with System;

with Tux.Types;
with Tux.Hashing;
with Tux.HMAC;
with Tux.HKDF;
with Tux.Keccak_1600;

with Support.Timing;

procedure Benchmark is

   Num_Repetitions : constant Positive := 500;
   Data_Size       : constant Positive := 256 * 1024;

   procedure Print_Cycles_Per_Byte
     (Data_Size : Natural;
      Cycles    : Support.Timing.Cycles_Count);

   procedure Benchmark_Hash
     (Buffer    : Tux.Types.Byte_Array;
      Algorithm : Tux.Hashing.Enabled_Algorithm_Kind);

   procedure Benchmark_HMAC
     (Buffer    : Tux.Types.Byte_Array;
      Algorithm : Tux.Hashing.Enabled_Algorithm_Kind);

   procedure Benchmark_HKDF
     (Buffer    : in out Tux.Types.Byte_Array;
      Algorithm :        Tux.Hashing.Enabled_Algorithm_Kind);

   generic
      Name : String;

      type Permutation_State is private;

      with procedure Initialize (State : out Permutation_State);

      with procedure Permute
        (State : in out Permutation_State);
   procedure Benchmark_Permutation;

   ---------------------------
   -- Print_Cycles_Per_Byte --
   ---------------------------

   procedure Print_Cycles_Per_Byte
     (Data_Size : Natural;
      Cycles    : Support.Timing.Cycles_Count)
   is
      type CPB_Number is delta 0.01 range 0.0 .. 2.0**System.Word_Size / 100.0;

      CPB : CPB_Number;

   begin
      CPB := CPB_Number (Cycles) / CPB_Number (Data_Size);

      Ada.Text_IO.Put (Support.Timing.Cycles_Count'Image (Cycles));
      Ada.Text_IO.Put (" cycles,");

      Ada.Text_IO.Put (Natural'Image (Data_Size));

      declare
         CPB_Str : constant String := CPB_Number'Image (CPB);
      begin
         Ada.Text_IO.Put (" bytes (" & CPB_Str (2 .. CPB_Str'Last));
      end;

      Ada.Text_IO.Put_Line (" cycles/byte)");
   end Print_Cycles_Per_Byte;

   --------------------
   -- Benchmark_Hash --
   --------------------

   procedure Benchmark_Hash
     (Buffer    : Tux.Types.Byte_Array;
      Algorithm : Tux.Hashing.Enabled_Algorithm_Kind)
   is
      use type Support.Timing.Cycles_Count;

      Hash_Len : constant Tux.Hashing.Hash_Length_Number :=
                   Tux.Hashing.Hash_Length (Algorithm);
      Hash     : Tux.Types.Byte_Array (1 .. Hash_Len);

      T       : Support.Timing.Time;
      Elapsed : Support.Timing.Cycles_Count;

      Min_Elapsed : Support.Timing.Cycles_Count :=
        Support.Timing.Cycles_Count'Last;

   begin
      Support.Timing.Calibrate;

      for I in Integer range 1 .. Num_Repetitions loop
         Support.Timing.Start_Measurement (T);
         Tux.Hashing.Compute_Hash (Algorithm, Buffer, Hash);
         Elapsed := Support.Timing.End_Measurement (T);

         if Elapsed < Min_Elapsed then
            Min_Elapsed := Elapsed;
         end if;
      end loop;

      Ada.Text_IO.Put (Tux.Hashing.Algorithm_Kind'Image (Algorithm));
      Ada.Text_IO.Put (": ");
      Print_Cycles_Per_Byte (Buffer'Length, Min_Elapsed);
   end Benchmark_Hash;

   --------------------
   -- Benchmark_HMAC --
   --------------------

   procedure Benchmark_HMAC
     (Buffer    : Tux.Types.Byte_Array;
      Algorithm : Tux.Hashing.Enabled_Algorithm_Kind)
   is
      use type Support.Timing.Cycles_Count;

      MAC_Len : constant Tux.HMAC.HMAC_Length_Number :=
                  Tux.HMAC.HMAC_Length (Algorithm);

      MAC : Tux.Types.Byte_Array (1 .. MAC_Len);
      Key : constant Tux.Types.Byte_Array (1 .. MAC_Len) := (others => 0);

      T       : Support.Timing.Time;
      Elapsed : Support.Timing.Cycles_Count;

      Min_Elapsed : Support.Timing.Cycles_Count :=
        Support.Timing.Cycles_Count'Last;

   begin
      Support.Timing.Calibrate;

      for I in Integer range 1 .. Num_Repetitions loop
         Support.Timing.Start_Measurement (T);
         Tux.HMAC.Compute_HMAC (Algorithm, Key, Buffer, MAC);
         Elapsed := Support.Timing.End_Measurement (T);

         if Elapsed < Min_Elapsed then
            Min_Elapsed := Elapsed;
         end if;
      end loop;

      Ada.Text_IO.Put ("HMAC-");
      Ada.Text_IO.Put (Tux.Hashing.Algorithm_Kind'Image (Algorithm));
      Ada.Text_IO.Put (": ");
      Print_Cycles_Per_Byte (Buffer'Length, Min_Elapsed);
   end Benchmark_HMAC;

   --------------------
   -- Benchmark_HKDF --
   --------------------

   procedure Benchmark_HKDF
     (Buffer    : in out Tux.Types.Byte_Array;
      Algorithm :        Tux.Hashing.Enabled_Algorithm_Kind)
   is
      use type Support.Timing.Cycles_Count;

      PRK_Length : constant Tux.HKDF.PRK_Length_Number :=
                     Tux.HKDF.PRK_Length (Algorithm);

      OKM_Length : constant Tux.HKDF.OKM_Length_Number :=
                     Tux.Types.Byte_Count'Min
                       (Tux.HKDF.Max_OKM_Length (Algorithm), Buffer'Length);
      --  Limit the max. OKM size to respect the precondition of HMAC.Expand

      PRK     : Tux.Types.Byte_Array (1 .. PRK_Length);
      T       : Support.Timing.Time;
      Elapsed : Support.Timing.Cycles_Count;

      Min_Elapsed : Support.Timing.Cycles_Count :=
        Support.Timing.Cycles_Count'Last;

   begin
      Support.Timing.Calibrate;

      for I in Integer range 1 .. Num_Repetitions loop
         Support.Timing.Start_Measurement (T);
         Tux.HKDF.Extract
           (Algorithm => Algorithm,
            Salt      => Tux.Types.Empty_Byte_Array,
            IKM       => Buffer,
            PRK       => PRK);
         Elapsed := Support.Timing.End_Measurement (T);

         if Elapsed < Min_Elapsed then
            Min_Elapsed := Elapsed;
         end if;
      end loop;

      Ada.Text_IO.Put ("HKDF-");
      Ada.Text_IO.Put (Tux.Hashing.Algorithm_Kind'Image (Algorithm));
      Ada.Text_IO.Put (" (Extract): ");
      Print_Cycles_Per_Byte (Buffer'Length, Min_Elapsed);

      Min_Elapsed := Support.Timing.Cycles_Count'Last;

      Support.Timing.Calibrate;

      for I in Integer range 1 .. Num_Repetitions loop
         Support.Timing.Start_Measurement (T);
         Tux.HKDF.Expand
           (Algorithm => Algorithm,
            PRK       => PRK,
            Info      => Tux.Types.Empty_Byte_Array,
            OKM       => Buffer (1 .. OKM_Length));
         Elapsed := Support.Timing.End_Measurement (T);

         if Elapsed < Min_Elapsed then
            Min_Elapsed := Elapsed;
         end if;
      end loop;

      Ada.Text_IO.Put ("HKDF-");
      Ada.Text_IO.Put (Tux.Hashing.Algorithm_Kind'Image (Algorithm));
      Ada.Text_IO.Put (" (Expand):  ");
      Print_Cycles_Per_Byte (OKM_Length, Min_Elapsed);
   end Benchmark_HKDF;

   ---------------------------
   -- Benchmark_Permutation --
   ---------------------------

   procedure Benchmark_Permutation is
      use type Support.Timing.Cycles_Count;

      State : Permutation_State;

      T       : Support.Timing.Time;
      Elapsed : Support.Timing.Cycles_Count;

      Min_Elapsed : Support.Timing.Cycles_Count :=
        Support.Timing.Cycles_Count'Last;
   begin

      Initialize (State);

      Support.Timing.Calibrate;

      for I in Integer range 1 .. Num_Repetitions * 100 loop
         Support.Timing.Start_Measurement (T);
         Permute (State);
         Elapsed := Support.Timing.End_Measurement (T);

         if Elapsed < Min_Elapsed then
            Min_Elapsed := Elapsed;
         end if;
      end loop;

      Ada.Text_IO.Put (Name);
      Ada.Text_IO.Put (":");
      Ada.Text_IO.Put (Support.Timing.Cycles_Count'Image (Min_Elapsed));
      Ada.Text_IO.Put_Line (" cycles");
   end Benchmark_Permutation;

   --------------------
   -- Instantiations --
   --------------------

   procedure Benchmark_Keccak_1600_24 is new Benchmark_Permutation
     (Name              => "Keccak-p[1600, 24]",
      Permutation_State => Tux.Keccak_1600.Keccak.Context,
      Initialize        => Tux.Keccak_1600.Keccak.Initialize,
      Permute           => Tux.Keccak_1600.Permute_24);

   procedure Benchmark_Keccak_1600_12 is new Benchmark_Permutation
     (Name              => "Keccak-p[1600, 12]",
      Permutation_State => Tux.Keccak_1600.Keccak.Context,
      Initialize        => Tux.Keccak_1600.Keccak.Initialize,
      Permute           => Tux.Keccak_1600.Permute_12);

   type Byte_Array_Access is access Tux.Types.Byte_Array;

   Data_Chunk : constant Byte_Array_Access :=
     new Tux.Types.Byte_Array (1 .. Data_Size);

   Lengths : constant array (1 .. 7) of Tux.Types.Byte_Count :=
      (1, 8, 64, 512, 4_096, 32_768, Data_Size);

begin
   Data_Chunk.all := (others => 16#AA#);

   for Length of Lengths loop
      Ada.Text_IO.Put_Line ("----------------------------------------");
      Ada.Text_IO.Put_Line ("Hash benchmarks");
      Ada.Text_IO.Put ("Data size =" & Tux.Types.Byte_Count'Image (Length));
      Ada.Text_IO.Put_Line (" bytes");
      Ada.Text_IO.New_Line;

      for Algorithm in Tux.Hashing.Algorithm_Kind loop
         if Algorithm in Tux.Hashing.Enabled_Algorithm_Kind then
            Benchmark_Hash (Data_Chunk.all (1 .. Length), Algorithm);
         end if;
      end loop;
      Ada.Text_IO.New_Line;

      for Algorithm in Tux.Hashing.Algorithm_Kind loop
         if Algorithm in Tux.Hashing.Enabled_Algorithm_Kind then
            Benchmark_HMAC (Data_Chunk.all (1 .. Length), Algorithm);
         end if;
      end loop;
      Ada.Text_IO.New_Line;

      for Algorithm in Tux.Hashing.Algorithm_Kind loop
         if Algorithm in Tux.Hashing.Enabled_Algorithm_Kind then
            Benchmark_HKDF (Data_Chunk.all (1 .. Length), Algorithm);
         end if;
      end loop;
      Ada.Text_IO.New_Line;
   end loop;

   Ada.Text_IO.Put_Line ("----------------------------------------");
   Ada.Text_IO.Put_Line ("Permutation benchmarks");
   Ada.Text_IO.New_Line;

   Benchmark_Keccak_1600_24;
   Benchmark_Keccak_1600_12;

end Benchmark;
