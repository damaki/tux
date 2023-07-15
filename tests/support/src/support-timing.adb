--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with System.Machine_Code; use System.Machine_Code;

package body Support.Timing is

   Measurement_Overhead : Cycles_Count;
   --  Stores the combined measured overhead of calling Start_Measurement and
   --  End_Measurement

   -----------
   -- RDTSC --
   -----------

   function RDTSC return Cycles_Count
   is
      L, H : Unsigned_32;
   begin
      Asm ("rdtsc",
           Outputs => (Unsigned_32'Asm_Output ("=a", L),
                       Unsigned_32'Asm_Output ("=d", H)),
           Volatile => True);

      return Shift_Left (Unsigned_64 (H), 32) or Unsigned_64 (L);
   end RDTSC;

   ---------------
   -- Calibrate --
   ---------------

   procedure Calibrate
   is
      T    : Time;
      Diff : Cycles_Count;
      Min  : Cycles_Count;

   begin
      Measurement_Overhead := 0;

      Start_Measurement (T);
      Min := End_Measurement (T);

      for N in 1 .. 100 loop
         Start_Measurement (T);
         Diff := End_Measurement (T);

         --  Keep the minimum
         if Diff < Min then
            Min := Diff;
         end if;
      end loop;

      Measurement_Overhead := Min;
   end Calibrate;

   -----------------------
   -- Start_Measurement --
   -----------------------

   procedure Start_Measurement (T : out Time)
   is
   begin
      T := Time (RDTSC);
   end Start_Measurement;

   ---------------------
   -- End_Measurement --
   ---------------------

   function End_Measurement (T : Time) return Cycles_Count
   is
      End_Time : Cycles_Count;

   begin
      End_Time := RDTSC;

      return (End_Time - Cycles_Count (T)) - Measurement_Overhead;
   end End_Measurement;

begin
   Calibrate;
end Support.Timing;
